// rasterize.js —— phantomjs 站点截图脚本（标准 rasterize 样板，通用技术表达，净室重写）。
// 用法: phantomjs rasterize.js <url> <outfile> [timeoutMs]
// 供 kernel/recon/native/screenshot.py 经 subprocess 驱动（进程边界，arm's-length 调用）。
var page = require('webpage').create();
var args = require('system').args;
var url = args[1];
var out = args[2];
var timeout = args[3] ? parseInt(args[3], 10) : 20000;

page.viewportSize = { width: 1280, height: 800 };
page.settings.resourceTimeout = timeout;
page.settings.userAgent =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36';

var done = false;
function finish(code) {
  if (done) return;
  done = true;
  phantom.exit(code);
}

// 硬超时兜底：渲染卡死也退出，避免进程悬挂
setTimeout(function () { finish(2); }, timeout + 5000);

page.open(url, function (status) {
  if (status !== 'success') { finish(1); return; }
  // 给页面一点渲染时间再截图
  setTimeout(function () {
    try { page.render(out); } catch (e) {}
    finish(0);
  }, 1500);
});
