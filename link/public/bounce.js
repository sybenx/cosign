// The page a sign-in code opens when Cosign isn't installed. It reads its own fragment
// (which never reached the server) and, if the code carries a nostrconnect:// fallback
// (`nc`), offers it to whatever signer app is installed. It acts on nothing by itself.
(function () {
  if (window.top !== window.self) return; // never inside another page's frame
  var params = new URLSearchParams(location.hash.slice(1));
  var nc = params.get('nc');
  if (!nc || nc.indexOf('nostrconnect://') !== 0) return;

  var site = params.get('origin');
  if (!site) { try { site = new URL(nc).searchParams.get('url') || new URL(nc).searchParams.get('name'); } catch (e) {} }
  if (site) document.getElementById('site').textContent = site.replace(/^https?:\/\//, '');

  document.getElementById('other').href = nc; // the nostrconnect: scheme opens Amber and the like
  document.getElementById('copy').onclick = function () {
    navigator.clipboard.writeText(nc).then(function () { document.getElementById('copied').hidden = false; });
  };
  document.title = 'Sign in with your phone';
  document.getElementById('about').hidden = true;
  document.getElementById('signin').hidden = false;
})();
