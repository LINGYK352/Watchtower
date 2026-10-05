// resources.js —— PhantomJS 低资源动态资源/XHR/最终 DOM 捕获。
// stdout 每行 JSON：{type,url} / {type:"dom",content}，由 Python adapter 结构化解析。
var page = require('webpage').create();
var args = require('system').args;
var url = args[1];
var timeout = args[2] ? parseInt(args[2], 10) : 40000;
var seen = {};
page.settings.resourceTimeout = timeout;
page.settings.userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36';
function emit(obj) { try { console.log(JSON.stringify(obj)); } catch (e) {} }
page.onResourceRequested = function(req) {
  if (!seen[req.url]) { seen[req.url] = true; emit({type: 'resource', url: req.url}); }
};
var done = false;
function finish(code) {
  if (done) return; done = true;
  try { emit({type: 'dom', content: page.content || ''}); } catch (e) {}
  phantom.exit(code);
}
setTimeout(function(){ finish(2); }, timeout + 5000);
page.open(url, function(status) {
  if (status !== 'success') { finish(1); return; }
  setTimeout(function(){ finish(0); }, 2500);
});
