const querystring = require("querystring");

// Returns a redirect to the OIDC Authorization Endpoint
// with the following query parameters:
// - client_id: From process.env.AUTH0_CLIENT_ID
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
        client_id: process.env['AUTH0_CLIENT_ID'],
        redirect_uri: `${scheme}://${http_host}/callback`,
        response_type: "code",
        scope: "openid profile",
        state: state,
    });

    // OIDC Authorization Endpoint
    let auth0_domain = r.variables.auth0_domain;
    let url = `https://${auth0_domain}/authorize`;

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
// - client_id: From process.env.AUTH0_CLIENT_ID
// - client_secret: From process.env.AUTH0_CLIENT_SECRET
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

    // exchange code for access tokens
    let scheme = r.variables.scheme;
    let http_host = r.variables.http_host;
    let qs = querystring.encode({
        grant_type: "authorization_code",
        client_id: process.env['AUTH0_CLIENT_ID'],
        client_secret: process.env['AUTH0_CLIENT_SECRET'],
        code: r.args['code'],
        redirect_uri: `${scheme}://${http_host}/callback`,
    });

    let auth0_domain = r.variables.auth0_domain;
    let url = `https://${auth0_domain}/oauth/token`;
    let token_response = await ngx.fetch(url, {
        method: "POST",
        body: qs,
        headers: {
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
        `access_token=${tokens.access_token}; Secure; HttpOnly; Max-Age=${tokens.expires_in}`,
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

// Verify if a request is authenticated
// An access token is retrieved from the session cookie,
// and used to retrieve the user profile from the OIDC Userinfo Endpoint
async function authenticate(r) {
    let auth0_domain = r.variables.auth0_domain;
    let access_token = r.variables.access_token;
    if (!access_token) {
        r.return(401, "");
        return
    }

    let url = `https://${auth0_domain}/userinfo`;
    let response = await ngx.fetch(url, {
        headers: {
            "Authorization": "Bearer " + access_token,
        },
    });

    let profile = await response.json();
    r.variables.auth_user = profile.nickname;
    r.variables.auth_email = profile.email || profile.name;
    r.variables.auth_unique_id = profile.sub;
    r.return(response.status, "Authenticated");
}

// When the session is over, logout the user from Auth0
function logout(r) {
    let auth0_domain = r.variables.auth0_domain;
    let logout_url = `https://${auth0_domain}/oidc/logout`;

    let scheme = r.variables.scheme;
    let http_host = r.variables.http_host;
    let qs = querystring.encode({
        post_logout_redirect_uri: `${scheme}://${http_host}/`,
    });

    let url = logout_url + "?" + qs;

    r.status = 302;
    r.headersOut['location'] = url;
    r.headersOut['set-cookie'] = [
        "access_token=; Secure; HttpOnly; Max-Age=0",
        "state=; Secure; HttpOnly; Max-Age=0",
    ];

    r.sendHeader();
    r.finish();
}

export default { authenticate, index, api, login, logout, callback};
