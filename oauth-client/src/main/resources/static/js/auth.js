function userHasToBeAuthenticated() {
    return localStorage.getItem("refresh_token") == null;
}

function refreshTokenIfRequired() {
    if (userHasToBeAuthenticated()) {
        window.location.href = authorizationUrl.href;
        return
    }

    const expiration = localStorage.getItem("access_token_expiration");
    const accessToken = localStorage.getItem("access_token");
    if (accessToken == null || expiration < Date.now()) {
        retrieveTokenWithRefreshToken();
    }
}

function retrieveTokenWithCode(code) {
    const settings = {
        "url": config["auth_server"] + "/oauth2/token",
        "method": "POST",
        "timeout": 0,
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": config["client_authorization"]
        },
        "data": {
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": config["redirect_uri"]
        },
        async: false
    };

    $.ajax(settings).done(function (response, status, xhr) {
        window.location.search = "";
        if (status === "success") {
            storeToken(response);
            storeUserInfo();
        } else {
            throw new Error("Unable to retrieve token");
        }
    });
}

function retrieveTokenWithRefreshToken() {
    const settings = {
        "url": config["auth_server"] + "/oauth2/token",
        "method": "POST",
        "timeout": 0,
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": config["client_authorization"]
        },
        "data": {
            "redirect_uri": config["redirect_uri"],
            "grant_type": "refresh_token",
            "refresh_token": localStorage.getItem('refresh_token'),
        },
    };

    $.ajax(settings).done(function (response, status) {
        if (status === "success") {
            storeToken(response);
            storeUserInfo()
        } else {
            throw new Error("Unable to retrieve token");
        }
    });
}

function storeToken(response) {
    localStorage.setItem('access_token', response.access_token);
    localStorage.setItem('refresh_token', response.refresh_token);
    localStorage.setItem('id_token', response.id_token);
    localStorage.setItem('access_token_expiration', Date.now() + response.expires_in * 1000);
}

function storeUserInfo() {
    console.log('user info')
    requestWithAuthentication(
        config["auth_server"] + "/userinfo",
        "GET",
        (response) => {
            localStorage.setItem("username", response.username);
            localStorage.setItem("game", response.game);
        }
    )
}

function logout() {
    localStorage.clear();
}

$(window).on("load", function () {
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get("code")) {
        const code = urlParams.get("code");
        console.log(code)
        retrieveTokenWithCode(code);
    }
})

