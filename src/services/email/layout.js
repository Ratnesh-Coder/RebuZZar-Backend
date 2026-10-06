const escapeHtml = require('../../utils/escapeHtml');

const e = escapeHtml;

/** Shared email shell (header / body / footer). Dynamic values must be escaped by the caller via e(). */
const shell = ({ headerBg, headerColor = '#ffffff', title, subtitle, body, footer, pad = 30, maxWidth = 650 }) => `
<div style="font-family: Arial, Helvetica, sans-serif; background:#f4f6f8; padding:${pad}px;">
  <div style="max-width:${maxWidth}px; margin:auto; background:#ffffff; border-radius:8px; overflow:hidden;">
    <div style="background:${headerBg}; color:${headerColor}; padding:20px ${pad}px;">
      <h2 style="margin:0;">${e(title)}</h2>
      ${subtitle ? `<p style="margin:5px 0 0;">${e(subtitle)}</p>` : ''}
    </div>
    <div style="padding:${pad}px; color:#333;">${body}</div>
    ${footer ? `<div style="background:#f1f1f1; padding:15px ${pad}px; font-size:12px; color:#666;">${e(footer)}</div>` : ''}
  </div>
</div>`;

/** rows: [label, value] (value escaped) or [label, html, true] for pre-built markup. */
const table = (rows) => `
<table style="width:100%; border-collapse:collapse; font-size:14px;">
  ${rows.map(([k, v, raw]) => `<tr><td><b>${e(k)}</b></td><td>${raw ? v : e(v)}</td></tr>`).join('\n  ')}
</table>`;

const date = (d) => e(new Date(d || Date.now()).toLocaleString());

module.exports = { shell, table, date, e };
