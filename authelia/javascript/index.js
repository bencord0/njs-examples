function index(r) {
    r.headersOut['Content-Type'] = 'text/plain';

    let remote_user = r.variables.auth_user;
    if (remote_user == null || remote_user == "") {
        remote_user = "World";
    }

    r.return(200, `Hello, ${remote_user}!`);
}

function api(r) {
    let remote_email = r.variables.auth_email;

    r.headersOut['Content-Type'] = 'application/json';
    r.return(200, JSON.stringify({
        "status": "OK",
        "email": remote_email,
    }));
}

async function authenticate(r) {
    let verification_endpoint = r.variables.verification_endpoint;
    let reply = await ngx.fetch(verification_endpoint, {
        headers: {"Cookie": r.headersIn.Cookie},
    });
    ngx.log(ngx.ERR, JSON.stringify(reply.headers));
    r.variables.auth_user = reply.headers.get("Remote-User");
    r.variables.auth_email = reply.headers.get("Remote-Email");
    r.return(reply.status, "");
}

export default { authenticate, index, api };
