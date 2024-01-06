Auth0 Flow


Client                  Server                             GitHub

GET /login -------------->

  <---------------- 307 Temporary Redirect
                    Location: https://github.com/login/oauth/authorize
                        ?client_id=...
                        &redirect_uri=http%3A%2F%2Flocahost%3A3000%2Fcallback
                        &login=...
                        &scope=user
                        &state=...
                    Set-Cookie: state=..., Path=/; Expires=...; Max-Age=....

GET /login/oauth/authorize?.... ----------------------------->

  <----------------------------------------- Login ---------->

  <----------------------------------------------------- 302 Redirect
                                                         Location: http://localhost:3000/callback
                                                            ?code=...
                                                            &state=...

GET /callback --------------->
    ?code=...
    &state=...
Cookie: state=...

                        POST https://github.com/login/oauth/access_token ------>
                        Accept: application/json
                        Content-Type: application/x-www-form-urlencoded
                        client_id=...&client_secret=...&code=...&redirect_uri=...
                        Docs: https://auth0.com/docs/api/authentication#authenticate-user

                        <------------------------------- 200 OK
                                                         Content-Type: application/json
                                                         { access_token, scope, token_type }

  <-------------------------- 307 Temporary Redirect
                              Location: /
                              Set-Cookie: access_token=..{jwt}..; Path=/; Expires=...; Max-Age=...

GET / ------------------->
Cookie: access_token=...

                        GET https://api.github.com/user ----->
                        Authentication: Bearer <access token>
                        <-------------------------------- 200 OK
                                                          Content-Type: application/json
                                                          {
                                                            login,
                                                            id,
                                                            node_id,
                                                            avatar_url,
                                                            gravatar_id,
                                                            url,
                                                            html_url,
                                                            followers_url,
                                                            following_url,
                                                            gists_url,
                                                            starred_url,
                                                            subscriptions_url,
                                                            organizations_url,
                                                            repos_url,
                                                            events_url,
                                                            received_events_url,
                                                            type,
                                                            site_admin,
                                                            name,
                                                            company,
                                                            blog,
                                                            location,
                                                            email,
                                                            hireable,
                                                            bio,
                                                            twitter_username,
                                                            public_repos,
                                                            public_gists,
                                                            followers,
                                                            following,
                                                            created_at,
                                                            updated_at
                                                          }

  <-------------------------- 200 OK (with data)
