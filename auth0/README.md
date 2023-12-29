Auth0 Flow


Client                  Server                             Auth0

GET /login -------------->

  <---------------- 307 Temporary Redirect
                    Location: https://condi.uk.auth0.com/authorize
                        ?client_id=...
                        &redirect_uri=http%3A%2F%2Flocahost%3A3000%2Fcallback
                        &response_type=code
                        &scope=openid+profile
                        &state=...
                    Set-Cookie: state=..., Path=/; Expires=...; Max-Age=....

GET /authorize?.... ----------------------------------------->

  <--------------------------------------------------------- 302 Redirect /u/login
  <----------------------------------------- Login ---------->

  <----------------------------------------------------- 302 Redirect
                                                         Location: http://localhost:3000/callback
                                                            ?code=...
                                                            &state=...
                                                         Set-Cookie: auth0=...; Path=/; Expires=...;HttpOnly; Secure; SameSite=None
                                                         Set-Cookie: auth0_compat=...; Path=/; Expires=...; HttpOnly; Secure

GET /callback --------------->
    ?code=...
    &state=...
Cookie: state=...

                        POST /oauth/token ------------------->
                        Content-Type: application/x-www-form-urlencoded
                        grant_type=authorization_code&client_id=...&client_secret=...&code=...&redirect_uri=...
                        Docs: https://auth0.com/docs/api/authentication#authenticate-user

                        <------------------------------- 200 OK
                                                         Content-Type: application/json
                                                         { access_token, refresh_token, id_token, token_type, expires_in }

  <-------------------------- 307 Temporary Redirect
                              Location: /
                              Set-Cookie: access_token=..{jwt}..; Path=/; Expires=...; Max-Age=...

GET / ------------------->
Cookie: access_token=...

                        GET /userinfo ----------------------->
                        Authentication: Bearer <access token>
                        <-------------------------------- 200 OK
                                                          Content-Type: application/json
                                                          { sub, nickname, name, picture, updated_at }

  <-------------------------- 200 OK (with data)
