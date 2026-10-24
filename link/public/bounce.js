// The page a sign-in code opens when Cosign isn't installed. It reads its own fragment
// (which never reached the server): for any sign-in code it offers Cosign, and if the
// code also carries a nostrconnect:// fallback (`nc`), it offers that to whatever signer
// app is installed. It acts on nothing by itself.
(function () {
  if (window.top !== window.self) return; // never inside another page's frame
  var params = new URLSearchParams(location.hash.slice(1));
  var nc = params.get('nc');
  if (nc && nc.indexOf('nostrconnect://') !== 0) nc = null;
  if (params.get('p') !== 'signer-ticket' && !nc) return; // not a sign-in code: the page about Cosign

  // Who's asking: the code's origin, or the fallback's url or name. A browser extension
  // can only claim https://<name>.extension; show it as "<Name> (browser extension)".
  var words = { iphone: 'iPhone', ipad: 'iPad', macbook: 'MacBook', macos: 'macOS', ios: 'iOS', pc: 'PC', on: 'on', 'in': 'in', 'for': 'for' };
  var site = params.get('origin');
  if (!site && nc) { try { var u = new URL(nc); site = u.searchParams.get('url') || u.searchParams.get('name'); } catch (e) {} }
  if (site) {
    var ext = /^https?:\/\/([a-z0-9-]+)\.extension\/?$/i.exec(site);
    site = ext
      ? ext[1].toLowerCase().split('-').filter(Boolean).map(function (w) { return words[w] || w[0].toUpperCase() + w.slice(1); }).join(' ') + ' (browser extension)'
      : site.replace(/^https?:\/\//, '');
    document.getElementById('site').textContent = site;
  }

  if (/iPhone|iPad|iPod/.test(navigator.userAgent)) {
    document.getElementById('get').hidden = true;
    document.getElementById('android').hidden = true;
    document.getElementById('ios').hidden = false;
    if (nc) document.getElementById('ios').textContent = 'Cosign is Android-only for now. If you have another signer app, use it below.';
  }
  if (nc) {
    document.getElementById('other').href = nc; // the nostrconnect: scheme opens Amber and the like
    document.getElementById('copy').onclick = function () {
      navigator.clipboard.writeText(nc).then(function () { document.getElementById('copied').hidden = false; });
    };
    document.getElementById('others').hidden = false;
  }
  document.title = 'Sign in with your phone';
  document.getElementById('about').hidden = true;
  document.getElementById('signin').hidden = false;
})();
