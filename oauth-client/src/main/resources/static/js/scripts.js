const config = {
    "auth_server": "http://localhost:7070",
    "client_id": "client",
    "secret": "secret",
    "response_type": "code",
    "scope": "openid profile",
    "redirect_uri": "http://localhost:8080/code"
}

$("#go").on("click", function () {
    const url = new URL(config["auth-server"] + "/oauth2/authorize");
    url.searchParams.set("client_id", config["client_id"]);
    url.searchParams.set("secret", config["secret"]);
    url.searchParams.set("scope", config["scope"]);
    url.searchParams.set("response_type", config["response_type"]);
    url.searchParams.set("redirect_uri", config["redirect_uri"]);

    window.location.href = url.href;
})

$(window).on("load", function () {
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get("code")) {
        console.log(urlParams.get("code"));
    }
})