/**
 * Minimal stateful in-memory stand-in for the MongoDB DRIVER (not for Mongoose): the real models and
 * controllers run on top of it, so state changes between requests. It implements only the filter and
 * update operators this backend uses. Results obtained with it are SIMULATED - they say nothing about
 * a real MongoDB server (atomicity, transactions, indexes).
 */
const { mock, mongoose, oid } = require('./helpers');

const norm = (v) => (v && v._bsontype === 'ObjectId' ? v.toString() : v instanceof Date ? v.getTime() : v);
const get = (doc, path) => {
  let cur = [doc];
  for (const key of path.split('.')) {
    cur = cur.flatMap((c) => (c == null ? [] : Array.isArray(c) ? c.map((x) => x?.[key]) : [c[key]])).flatMap((x) => x);
  }
  return cur;
};
const same = (a, b) => norm(a) === norm(b);

const matchValue = (values, cond) => {
  const present = values.filter((v) => v !== undefined);
  if (cond instanceof RegExp) return present.some((v) => typeof v === 'string' && cond.test(v));
  if (cond !== null && typeof cond === 'object' && !(cond instanceof Date) && cond._bsontype !== 'ObjectId' && !Array.isArray(cond)) {
    const keys = Object.keys(cond).filter((k) => k.startsWith('$'));
    if (keys.length) {
      return keys.every((op) => {
        const arg = cond[op];
        switch (op) {
          case '$ne': return !present.some((v) => same(v, arg));
          case '$in': return present.some((v) => arg.some((a) => same(v, a)));
          case '$exists': return arg ? present.length > 0 : present.length === 0;
          case '$lte': return present.some((v) => norm(v) <= norm(arg));
          case '$gt': return present.some((v) => norm(v) > norm(arg));
          case '$regex': { const re = new RegExp(arg instanceof RegExp ? arg.source : arg, cond.$options || (arg instanceof RegExp ? arg.flags : '')); return present.some((v) => typeof v === 'string' && re.test(v)); }
          case '$options': return true; // consumed together with $regex
          default: throw new Error(`fakedb: unsupported operator ${op}`);
        }
      });
    }
  }
  return present.some((v) => same(v, cond)) || (cond === null && present.length === 0);
};

const matches = (doc, filter) => Object.entries(filter || {}).every(([k, cond]) => {
  if (k === '$or') return cond.some((f) => matches(doc, f));
  if (k === '$and') return cond.every((f) => matches(doc, f));
  return matchValue(get(doc, k), cond);
});

const clone = (d) => (d == null ? d : structuredCloneDoc(d));
const structuredCloneDoc = (d) => {
  if (d === null || typeof d !== 'object') return d;
  if (d._bsontype === 'ObjectId' || d instanceof Date) return d;
  if (Array.isArray(d)) return d.map(structuredCloneDoc);
  return Object.fromEntries(Object.entries(d).map(([k, v]) => [k, structuredCloneDoc(v)]));
};

const setPath = (doc, path, value) => {
  const keys = path.split('.'); let cur = doc;
  keys.slice(0, -1).forEach((k) => { cur[k] = cur[k] ?? {}; cur = cur[k]; });
  cur[keys.at(-1)] = value;
};

/** Resolve the positional operator: `items.$.quantity` -> `items.<index>.quantity`, using the query's `items.*` conditions. */
const resolvePositional = (doc, path, filter) => {
  if (!path.includes('.$.')) return path;
  const [arrPath, rest] = path.split('.$.');
  const arr = get(doc, arrPath)[0] ?? [];
  const sub = {};
  for (const [k, v] of Object.entries(filter || {})) if (k.startsWith(`${arrPath}.`)) sub[k.slice(arrPath.length + 1)] = v;
  const idx = (doc[arrPath] || arr).findIndex((el) => matches(el, sub));
  if (idx < 0) throw new Error('fakedb: positional operator used but the query did not match an array element');
  return `${arrPath}.${idx}.${rest}`;
};

const applyUpdate = (doc, update, filter) => {
  for (const [op, body] of Object.entries(update)) {
    if (op === '$set') for (const [k, v] of Object.entries(body)) setPath(doc, resolvePositional(doc, k, filter), v);
    else if (op === '$unset') for (const k of Object.keys(body)) delete doc[k];
    else if (op === '$inc') for (const [k, v] of Object.entries(body)) { const rp = resolvePositional(doc, k, filter); setPath(doc, rp, (get(doc, rp)[0] || 0) + v); }
    else if (op === '$push') for (const [k, v] of Object.entries(body)) { doc[k] = [...(doc[k] || []), structuredCloneDoc(v)]; }
    else if (op === '$pull') for (const [k, cond] of Object.entries(body)) { doc[k] = (doc[k] || []).filter((el) => !matches(el, cond)); }
    else if (op === '$setOnInsert') { /* only applied by upserts */ }
    else throw new Error(`fakedb: unsupported update operator ${op}`);
  }
  return doc;
};

/** Document an upsert would insert: equality fields of the filter + $setOnInsert + the other operators. */
const upsertDoc = (filter, update, oidFn) => {
  const base = { _id: oidFn() };
  for (const [k, v] of Object.entries(filter || {})) if (!k.startsWith('$') && !k.includes('.') && (v === null || typeof v !== 'object' || v._bsontype === 'ObjectId' || v instanceof Date)) base[k] = v;
  for (const [k, v] of Object.entries(update.$setOnInsert || {})) base[k] = structuredCloneDoc(v);
  return applyUpdate(base, { ...update, $setOnInsert: undefined }, filter);
};

/** Attach the fake driver to the given models. Returns { store, reset }. */
const attach = (models) => {
  const store = {};
  for (const Model of models) {
    const name = Model.collection.name; store[name] = [];
    const rows = store[name];
    const c = Model.collection;
    mock.method(c, 'find', (f) => ({ toArray: async () => rows.filter((d) => matches(d, f)).map(clone) }));
    mock.method(c, 'findOne', async (f) => clone(rows.find((d) => matches(d, f))) ?? null);
    mock.method(c, 'insertOne', async (doc) => { doc._id = doc._id || oid(); rows.push(clone(doc)); return { acknowledged: true, insertedId: doc._id }; });
    mock.method(c, 'updateOne', async (f, u, o) => {
      const d = rows.find((x) => matches(x, f));
      if (d) applyUpdate(d, u, f);
      else if (o && o.upsert) rows.push(upsertDoc(f, u, oid));
      return { acknowledged: true, matchedCount: d ? 1 : 0, modifiedCount: d ? 1 : 0, upsertedCount: !d && o && o.upsert ? 1 : 0 };
    });
    mock.method(c, 'updateMany', async (f, u) => { const ds = rows.filter((x) => matches(x, f)); ds.forEach((d) => applyUpdate(d, u, f)); return { acknowledged: true, matchedCount: ds.length, modifiedCount: ds.length }; });
    mock.method(c, 'findOneAndUpdate', async (f, u, o) => {
      let d = rows.find((x) => matches(x, f));
      if (!d && o && o.upsert) { d = upsertDoc(f, u, oid); rows.push(d); return clone(d); }
      if (!d) return null;
      applyUpdate(d, u, f);
      return clone(d);
    });
    mock.method(c, 'deleteOne', async (f) => { const i = rows.findIndex((x) => matches(x, f)); if (i >= 0) rows.splice(i, 1); return { acknowledged: true, deletedCount: i >= 0 ? 1 : 0 }; });
  }
  // Transactions are not simulated: run the callback directly (a real server would roll back on throw).
  mock.method(mongoose, 'startSession', async () => ({
    id: 'fake', inTransaction: () => true, transaction: { state: 'TRANSACTION_IN_PROGRESS' },
    withTransaction: async (fn) => fn(), endSession: async () => {},
  }));
  return { store, seed: (Model, doc) => { const d = (doc.toObject ? doc.toObject() : doc); store[Model.collection.name].push(clone(d)); return d; } };
};

module.exports = { attach, matches, applyUpdate };
