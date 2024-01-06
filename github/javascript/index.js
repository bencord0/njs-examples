const querystring = require("querystring");

// Returns a redirect to the OIDC Authorization Endpoint
// with the following query parameters:
// - client_id: From process.env.GITHUB_CLIENT_ID
// - redirect_uri: The public URL to our callback endpoint
// - response_type: "code" - The authorization flow we are using
// - scope: "openid profile" - The scopes we are requesting access to
// - state: A random string we generate to protect against CSRF attacks
function login(r) {
    let buffer = new Int8Array(16);
    crypto.getRandomValues(buffer);
    let state = Buffer.from(buffer).toString("hex");

    let scheme = r.variables.scheme;
    let http_host = r.variables.http_host;
    let qs = querystring.encode({
        client_id: process.env['GITHUB_CLIENT_ID'],
        redirect_uri: `${scheme}://${http_host}/callback`,
        //scope: "user",
        state: state,
    });

    // OIDC Authorization Endpoint
    let url = "https://github.com/login/oauth/authorize";

    r.status = 302;
    r.headersOut['location'] = url + "?" + qs;
    r.headersOut['set-cookie'] = `state=${state}; Secure; HttpOnly; Max-Age=300`;

    r.sendHeader();
    r.finish();
}

// Converts an authorization code for a set of access tokens
// Expects to be given the following query parameters:
// - code: The authorization code we received from the OIDC Authorization Endpoint
// - state: The state we sent to the OIDC Authorization Endpoint
// state needs to be checked by us to prevent CSRF attacks
// code needs to be exchanged for access tokens
//
// The OIDC Token Endpoint expects the following parameters:
// - grant_type: "authorization_code"
// - client_id: From process.env.GITHUB_CLIENT_ID
// - client_secret: From process.env.GITHUB_CLIENT_SECRET
// - code: The authorization code we received from the OIDC Authorization Endpoint
// - redirect_uri: The public URL to our callback endpoint
//
// The OIDC Token Endpoint will return the following:
// - access_token: A opaque (secretly symmetrically encrypted) JWT that can be used to authenticate requests
// - id_token: A signed and decodable JWT that contains information about the user
// - token_type: "Bearer" - The type of token we received
// - expires_in: The number of seconds until the access_token expires
// - scope: The scopes that were granted to the access_token
// - refresh_token: A JWT that can be used to refresh the access_token
async function callback(r) {
    // check state to prevent CSRF attacks
    if (r.variables['state'] !== r.args['state'] && r.args['state'] !== "") {
        r.return(400, "Invalid state");
    }

    let scheme = r.variables.scheme;
    let http_host = r.variables.http_host;

    // exchange code for access tokens
    let qs = querystring.encode({
        client_id: process.env['GITHUB_CLIENT_ID'],
        client_secret: process.env['GITHUB_CLIENT_SECRET'],
        code: r.args['code'],
        redirect_uri: `${scheme}://${http_host}/callback`,
    });

    let url = "https://github.com/login/oauth/access_token";
    let token_response = await ngx.fetch(url, {
        method: "POST",
        body: qs,
        headers: {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    });

    if (token_response.status !== 200) {
        r.return(500, "Failed to get access tokens");
    }

    let tokens = await token_response.json();

    r.status = 302;
    r.headersOut['location'] = "/";
    r.headersOut['set-cookie'] = [
        `access_token=${tokens.access_token}; Secure; HttpOnly`,
        "state=; Secure; HttpOnly; Max-Age=0",
    ];

    r.sendHeader();
    r.finish();
}

function index(r) {
    r.headersOut['content-type'] = "text/plain";

    let auth_user = r.variables.auth_user;
    if (auth_user == "") {
        auth_user = "World";
    }

    r.return(200, `Hello ${auth_user}!`);
}

function api(r) {
    r.headersOut['content-type'] = "application/json";
    r.return(200, JSON.stringify({
        id: r.variables.auth_unique_id,
        name: r.variables.auth_user,
        email: r.variables.auth_email,
    }));
}

async function authenticate(r) {
    let access_token = r.variables['access_token'];
    if (!access_token) {
        r.return(401, "");
        return
    }

    let url = "https://api.github.com/user";
    let response = await ngx.fetch(url, {
        headers: {
            "Authorization": "Bearer " + access_token,
            "User-Agent": "local.condi.me",
        },
    });

    let profile = await response.json();

    r.variables.auth_user = profile.name;
    r.variables.auth_email = profile.email || await getEmail(r);
    r.variables.auth_unique_id = profile.id;
    r.return(response.status, "Authenticated");
}

async function getEmail(r) {
    let access_token = r.variables['access_token'];
    if (!access_token) {
        return ""
    }

    let url = "https://api.github.com/user/public_emails";
    let response = await ngx.fetch(url, {
        headers: {
            "Authorization": "Bearer " + access_token,
            "User-Agent": "local.condi.me",
        },
    });

    let emails = await response.json();
    if (emails.length == 0) {
        return ""
    }

    return emails[0].email;
}

function logout(r) {
    let scheme = r.variables.scheme;
    let http_host = r.variables.http_host;
    let logout_url = `${scheme}://${http_host}/`;

    r.status = 302;
    r.headersOut['location'] = logout_url;
    r.headersOut['set-cookie'] = [
        "access_token=; Secure; HttpOnly; Max-Age=0",
        "state=; Secure; HttpOnly; Max-Age=0",
    ];

    r.sendHeader();
    r.finish();
}

export default { authenticate, index, api, login, logout, callback};
