function index(r) {
    r.headersOut['Content-Type'] = 'text/plain';
    r.return(200, "index");
}

function api(r) {
    r.headersOut['Content-Type'] = 'application/json';
    r.return(200, JSON.stringify({"status": "OK"}));
}

async function authenticate(r) {
    let reply = await ngx.fetch("https://auth.condi.me/api/verify", {
        headers: {"Cookie": r.headersIn.Cookie},
    });
    r.return(reply.status, "");
}

export default { authenticate, index, api };
