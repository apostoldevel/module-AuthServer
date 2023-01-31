/*++

Program name:

  Apostol Web Service

Module Name:

  AuthServer.cpp

Notices:

  Module: OAuth 2 Authorization Server

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

//----------------------------------------------------------------------------------------------------------------------

#include "Core.hpp"
#include "AuthServer.hpp"
//----------------------------------------------------------------------------------------------------------------------

#include "jwt.h"
//----------------------------------------------------------------------------------------------------------------------

#define WEB_APPLICATION_NAME "web"
#define SERVICE_APPLICATION_NAME "service"

extern "C++" {

namespace Apostol {

    namespace Module {

        //--------------------------------------------------------------------------------------------------------------

        //-- CAuthServer -----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        CAuthServer::CAuthServer(CModuleProcess *AProcess) : CApostolModule(AProcess, "authorization server", "module/AuthServer") {
            m_Headers.Add("Authorization");
            m_FixedDate = Now();

            CAuthServer::InitMethods();
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::InitMethods() {
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            m_Methods.AddObject(_T("GET")    , (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoGet(Connection); }));
            m_Methods.AddObject(_T("POST")   , (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoPost(Connection); }));
            m_Methods.AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoOptions(Connection); }));
            m_Methods.AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
#else
            m_Methods.AddObject(_T("GET")    , (CObject *) new CMethodHandler(true , std::bind(&CAuthServer::DoGet, this, _1)));
            m_Methods.AddObject(_T("POST")   , (CObject *) new CMethodHandler(true , std::bind(&CAuthServer::DoPost, this, _1)));
            m_Methods.AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(true , std::bind(&CAuthServer::DoOptions, this, _1)));
            m_Methods.AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, std::bind(&CAuthServer::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, std::bind(&CAuthServer::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, std::bind(&CAuthServer::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, std::bind(&CAuthServer::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, std::bind(&CAuthServer::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, std::bind(&CAuthServer::MethodNotAllowed, this, _1)));
#endif
        }
        //--------------------------------------------------------------------------------------------------------------

        CHTTPReply::CStatusType CAuthServer::ErrorCodeToStatus(int ErrorCode) {
            CHTTPReply::CStatusType Status = CHTTPReply::ok;

            if (ErrorCode != 0) {
                switch (ErrorCode) {
                    case 401:
                        Status = CHTTPReply::unauthorized;
                        break;

                    case 403:
                        Status = CHTTPReply::forbidden;
                        break;

                    case 404:
                        Status = CHTTPReply::not_found;
                        break;

                    case 500:
                        Status = CHTTPReply::internal_server_error;
                        break;

                    default:
                        Status = CHTTPReply::bad_request;
                        break;
                }
            }

            return Status;
        }
        //--------------------------------------------------------------------------------------------------------------

        int CAuthServer::CheckError(const CJSON &Json, CString &ErrorMessage, bool RaiseIfError) {
            int ErrorCode = 0;

            if (Json.HasOwnProperty(_T("error"))) {
                const auto& error = Json[_T("error")];

                if (error.HasOwnProperty(_T("code"))) {
                    ErrorCode = error[_T("code")].AsInteger();
                } else {
                    ErrorCode = 40000;
                }

                if (error.HasOwnProperty(_T("message"))) {
                    ErrorMessage = error[_T("message")].AsString();
                } else {
                    ErrorMessage = _T("Invalid request.");
                }

                if (RaiseIfError)
                    throw EDBError(ErrorMessage.c_str());

                if (ErrorCode >= 10000)
                    ErrorCode = ErrorCode / 100;

                if (ErrorCode < 0)
                    ErrorCode = 400;
            }

            return ErrorCode;
        }
        //--------------------------------------------------------------------------------------------------------------

        int CAuthServer::CheckOAuth2Error(const CJSON &Json, CString &Error, CString &ErrorDescription) {
            int ErrorCode = 0;

            if (Json.HasOwnProperty(_T("error"))) {
                const auto& error = Json[_T("error")];

                if (error.HasOwnProperty(_T("code"))) {
                    ErrorCode = error[_T("code")].AsInteger();
                } else {
                    ErrorCode = 400;
                }

                if (error.HasOwnProperty(_T("error"))) {
                    Error = error[_T("error")].AsString();
                } else {
                    Error = _T("invalid_request");
                }

                if (error.HasOwnProperty(_T("message"))) {
                    ErrorDescription = error[_T("message")].AsString();
                } else {
                    ErrorDescription = _T("Invalid request.");
                }
            }

            return ErrorCode;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::AfterQuery(CHTTPServerConnection *AConnection, const CString &Path, const CJSON &Payload) {
            if (Path == _T("/sign/in/token")) {
                SetAuthorizationData(AConnection, Payload);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::DoPostgresQueryExecuted(CPQPollQuery *APollQuery) {

            auto pResult = APollQuery->Results(0);

            if (pResult->ExecStatus() != PGRES_TUPLES_OK) {
                QueryException(APollQuery, Delphi::Exception::EDBError(pResult->GetErrorMessage()));
                return;
            }

            CString ErrorMessage;

            auto pConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->Binding());

            if (pConnection != nullptr && !pConnection->ClosedGracefully()) {

                const auto& Path = pConnection->Data()["path"].Lower();

                const auto &caRequest = pConnection->Request();
                auto &Reply = pConnection->Reply();

                const auto& result_object = caRequest.Params[_T("result_object")];
                const auto& data_array = caRequest.Params[_T("data_array")];

                CHTTPReply::CStatusType status = CHTTPReply::ok;

                try {
                    if (pResult->nTuples() == 1) {
                        const CJSON Payload(pResult->GetValue(0, 0));
                        status = ErrorCodeToStatus(CheckError(Payload, ErrorMessage));
                        if (status == CHTTPReply::ok) {
                            AfterQuery(pConnection, Path, Payload);
                        }
                    }

                    PQResultToJson(pResult, Reply.Content);
                } catch (Delphi::Exception::Exception &E) {
                    ErrorMessage = E.what();
                    status = CHTTPReply::bad_request;
                    Log()->Error(APP_LOG_ERR, 0, "%s", E.what());
                }

                const auto& caRedirect = status == CHTTPReply::ok ? pConnection->Data()["redirect"] : pConnection->Data()["redirect_error"];

                if (caRedirect.IsEmpty()) {
                    if (status == CHTTPReply::ok) {
                        pConnection->SendReply(status, nullptr, true);
                    } else {
                        ReplyError(pConnection, status, "server_error", ErrorMessage);
                    }
                } else {
                    if (status == CHTTPReply::ok) {
                        Redirect(pConnection, caRedirect, true);
                    } else {
                        switch (status) {
                            case CHTTPReply::unauthorized:
                                RedirectError(pConnection, caRedirect, status, "unauthorized_client", ErrorMessage);
                                break;

                            case CHTTPReply::forbidden:
                                RedirectError(pConnection, caRedirect, status, "access_denied", ErrorMessage);
                                break;

                            case CHTTPReply::internal_server_error:
                                RedirectError(pConnection, caRedirect, status, "server_error", ErrorMessage);
                                break;

                            default:
                                RedirectError(pConnection, caRedirect, status, "invalid_request", ErrorMessage);
                                break;
                        }
                    }
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::QueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {

            auto pConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->Binding());

            if (pConnection != nullptr && !pConnection->ClosedGracefully()) {
                auto &Reply = pConnection->Reply();

                const auto& caRedirect = pConnection->Data()["redirect_error"];

                if (!caRedirect.IsEmpty()) {
                    RedirectError(pConnection, caRedirect, CHTTPReply::internal_server_error, "server_error", E.what());
                } else {
                    ExceptionToJson(CHTTPReply::internal_server_error, E, Reply.Content);
                    pConnection->SendReply(CHTTPReply::ok, nullptr, true);
                }
            }

            Log()->Error(APP_LOG_ERR, 0, "%s", E.what());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::DoPostgresQueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
            QueryException(APollQuery, E);
        }
        //--------------------------------------------------------------------------------------------------------------

        CString CAuthServer::CreateToken(const CCleanToken& CleanToken) {
            const auto& Providers = Server().Providers();
            const auto& Default = Providers.Default().Value();
            const CString Application(WEB_APPLICATION_NAME);
            auto token = jwt::create()
                    .set_issuer(Default.Issuer(Application))
                    .set_audience(Default.ClientId(Application))
                    .set_issued_at(std::chrono::system_clock::now())
                    .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{3600})
                    .sign(jwt::algorithm::hs256{std::string(Default.Secret(Application))});

            return token;
        }
        //--------------------------------------------------------------------------------------------------------------

        CString CAuthServer::VerifyToken(const CString &Token) {

            const auto& GetSecret = [](const CProvider &Provider, const CString &Application) {
                const auto &Secret = Provider.Secret(Application);
                if (Secret.IsEmpty())
                    throw ExceptionFrm("Not found Secret for \"%s:%s\"", Provider.Name().c_str(), Application.c_str());
                return Secret;
            };

            auto decoded = jwt::decode(Token);
            const auto& aud = CString(decoded.get_audience());

            CString Application;

            const auto& Providers = Server().Providers();

            const auto Index = OAuth2::Helper::ProviderByClientId(Providers, aud, Application);
            if (Index == -1)
                throw COAuth2Error(_T("Not found provider by Client ID."));

            const auto& provider = Providers[Index].Value();

            const auto& iss = CString(decoded.get_issuer());

            CStringList Issuers;
            provider.GetIssuers(Application, Issuers);
            if (Issuers[iss].IsEmpty())
                throw jwt::token_verification_exception("Token doesn't contain the required issuer.");

            const auto& alg = decoded.get_algorithm();
            const auto& ch = alg.substr(0, 2);

            const auto& Secret = GetSecret(provider, Application);

            if (ch == "HS") {
                if (alg == "HS256") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::hs256{Secret});
                    verifier.verify(decoded);

                    return Token; // if algorithm HS256
                } else if (alg == "HS384") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::hs384{Secret});
                    verifier.verify(decoded);
                } else if (alg == "HS512") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::hs512{Secret});
                    verifier.verify(decoded);
                }
            } else if (ch == "RS") {

                const auto& kid = decoded.get_key_id();
                const auto& key = OAuth2::Helper::GetPublicKey(Providers, kid);

                if (alg == "RS256") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::rs256{key});
                    verifier.verify(decoded);
                } else if (alg == "RS384") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::rs384{key});
                    verifier.verify(decoded);
                } else if (alg == "RS512") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::rs512{key});
                    verifier.verify(decoded);
                }
            } else if (ch == "ES") {

                const auto& kid = decoded.get_key_id();
                const auto& key = OAuth2::Helper::GetPublicKey(Providers, kid);

                if (alg == "ES256") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::es256{key});
                    verifier.verify(decoded);
                } else if (alg == "ES384") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::es384{key});
                    verifier.verify(decoded);
                } else if (alg == "ES512") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::es512{key});
                    verifier.verify(decoded);
                }
            } else if (ch == "PS") {

                const auto& kid = decoded.get_key_id();
                const auto& key = OAuth2::Helper::GetPublicKey(Providers, kid);

                if (alg == "PS256") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::ps256{key});
                    verifier.verify(decoded);
                } else if (alg == "PS384") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::ps384{key});
                    verifier.verify(decoded);
                } else if (alg == "PS512") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::ps512{key});
                    verifier.verify(decoded);
                }
            }

            const auto& Result = CCleanToken(R"({"alg":"HS256","typ":"JWT"})", decoded.get_payload(), true);

            return Result.Sign(jwt::algorithm::hs256{Secret});
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CAuthServer::CheckAuthorization(CHTTPServerConnection *AConnection, CAuthorization &Authorization) {

            const auto &caRequest = AConnection->Request();

            try {
                if (CheckAuthorizationData(caRequest, Authorization)) {
                    if (Authorization.Schema == CAuthorization::asBearer) {
                        VerifyToken(Authorization.Token);
                        return true;
                    }
                }

                if (Authorization.Schema == CAuthorization::asBasic)
                    AConnection->Data().Values("Authorization", "Basic");

                ReplyError(AConnection, CHTTPReply::unauthorized, "unauthorized", "Unauthorized.");
            } catch (jwt::token_expired_exception &e) {
                ReplyError(AConnection, CHTTPReply::forbidden, "forbidden", e.what());
            } catch (jwt::token_verification_exception &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, "invalid_request", e.what());
            } catch (CAuthorizationError &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, "invalid_request", e.what());
            } catch (std::exception &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, "invalid_request", e.what());
            }

            return false;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::DoIdentifier(CHTTPServerConnection *AConnection) {

            auto OnExecuted = [AConnection](CPQPollQuery *APollQuery) {

                auto &Reply = AConnection->Reply();
                auto pResult = APollQuery->Results(0);

                CString errorMessage;
                CHTTPReply::CStatusType status = CHTTPReply::internal_server_error;

                try {
                    if (pResult->ExecStatus() != PGRES_TUPLES_OK)
                        throw Delphi::Exception::EDBError(pResult->GetErrorMessage());

                    Reply.ContentType = CHTTPReply::json;
                    Reply.Content = pResult->GetValue(0, 0);

                    const CJSON Payload(Reply.Content);
                    status = ErrorCodeToStatus(CheckError(Payload, errorMessage));
                } catch (Delphi::Exception::Exception &E) {
                    Reply.Content.Clear();
                    ExceptionToJson(status, E, Reply.Content);
                    Log()->Error(APP_LOG_ERR, 0, "%s", E.what());
                }

                AConnection->SendReply(status, nullptr, true);
            };

            auto OnException = [AConnection](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                ReplyError(AConnection, CHTTPReply::internal_server_error, "server_error", E.what());
            };

            const auto &caRequest = AConnection->Request();

            CJSON Json;
            ContentToJson(caRequest, Json);

            const auto &Identifier = Json["value"].AsString();

            if (Identifier.IsEmpty()) {
                ReplyError(AConnection, CHTTPReply::bad_request, "invalid_request", "Invalid request.");
                return;
            }

            CAuthorization Authorization;
            if (CheckAuthorization(AConnection, Authorization)) {
                if (Authorization.Schema == CAuthorization::asBearer) {
                    CStringList SQL;

                    SQL.Add(CString().Format("SELECT * FROM daemon.identifier(%s, %s);",
                            PQQuoteLiteral(Authorization.Token).c_str(),
                            PQQuoteLiteral(Identifier).c_str()
                    ));

                    try {
                        ExecSQL(SQL, nullptr, OnExecuted, OnException);
                    } catch (Delphi::Exception::Exception &E) {
                        ReplyError(AConnection, CHTTPReply::service_unavailable, "temporarily_unavailable", "Temporarily unavailable.");
                    }

                    return;
                }

                ReplyError(AConnection, CHTTPReply::unauthorized, "unauthorized", "Unauthorized.");
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::RedirectError(CHTTPServerConnection *AConnection, const CString &Location, int ErrorCode, const CString &Error, const CString &Message) {
            CString errorLocation(Location);

            errorLocation << "?code=" << ErrorCode;
            errorLocation << "&error=" << Error;
            errorLocation << "&error_description=" << CHTTPServer::URLEncode(Message);

            Redirect(AConnection, errorLocation, true);

            Log()->Error(APP_LOG_ERR, 0, _T("RedirectError: %s"), Message.c_str());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::ReplyError(CHTTPServerConnection *AConnection, int ErrorCode, const CString &Error, const CString &Message) {
            auto &Reply = AConnection->Reply();

            Reply.ContentType = CHTTPReply::json;

            CHTTPReply::CStatusType Status = ErrorCodeToStatus(ErrorCode);

            if (ErrorCode == CHTTPReply::unauthorized) {
                CHTTPReply::AddUnauthorized(Reply, true, "access_denied", Message.c_str());
            }

            Reply.Content.Clear();
            Reply.Content.Format(R"({"error": "%s", "error_description": "%s"})",
                                   Error.c_str(), Delphi::Json::EncodeJsonString(Message).c_str());

            AConnection->SendReply(Status, nullptr, true);

            Log()->Notice(_T("ReplyError: %s"), Message.c_str());
        };
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::DoToken(CHTTPServerConnection *AConnection) {

            auto OnExecuted = [AConnection](CPQPollQuery *APollQuery) {

                auto &Reply = AConnection->Reply();
                auto pResult = APollQuery->Results(0);

                CString error;
                CString errorDescription;

                CHTTPReply::CStatusType status;

                try {
                    if (pResult->ExecStatus() != PGRES_TUPLES_OK)
                        throw Delphi::Exception::EDBError(pResult->GetErrorMessage());

                    PQResultToJson(pResult, Reply.Content);

                    const CJSON Json(Reply.Content);
                    status = ErrorCodeToStatus(CheckOAuth2Error(Json, error, errorDescription));

                    if (status == CHTTPReply::ok) {
                        const auto &session = Json[_T("session")].AsString();
                        if (!session.IsEmpty())
                            Reply.SetCookie(_T("SID"), session.c_str(), _T("/"), 60 * SecsPerDay);

                        AConnection->SendReply(status, nullptr, true);
                    } else {
                        ReplyError(AConnection, status, error, errorDescription);
                    }
                } catch (Delphi::Exception::Exception &E) {
                    ReplyError(AConnection, CHTTPReply::internal_server_error, "server_error", E.what());
                }
            };

            auto OnException = [AConnection](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                ReplyError(AConnection, CHTTPReply::internal_server_error, "server_error", E.what());
            };

            LPCTSTR js_origin_error = _T("The JavaScript origin in the request, %s, does not match the ones authorized for the OAuth client.");
            LPCTSTR redirect_error = _T("Invalid parameter value for redirect_uri: Non-public domains not allowed: %s");
            LPCTSTR value_error = _T("Parameter value %s cannot be empty.");

            const auto &caRequest = AConnection->Request();

            CJSON Json;
            ContentToJson(caRequest, Json);

            CAuthorization Authorization;

            const auto &grant_type = Json["grant_type"].AsString();

            if (grant_type != "urn:ietf:params:oauth:grant-type:jwt-bearer") {

                const auto &client_id = Json["client_id"].AsString();
                const auto &client_secret = Json["client_secret"].AsString();
                const auto &redirect_uri = Json["redirect_uri"].AsString();

                const auto &authorization = caRequest.Headers["Authorization"];
                const auto &origin = GetOrigin(AConnection);
                const auto &providers = Server().Providers();

                if (authorization.IsEmpty()) {
                    Authorization.Schema = CAuthorization::asBasic;
                    Authorization.Username = client_id;
                    Authorization.Password = client_secret;
                } else {
                    Authorization << authorization;

                    if (Authorization.Schema != CAuthorization::asBasic) {
                        ReplyError(AConnection, CHTTPReply::bad_request, "invalid_request",
                                   "Invalid authorization schema.");
                        return;
                    }
                }

                if (Authorization.Username.IsEmpty()) {
                    if (grant_type != "password") {
                        ReplyError(AConnection, CHTTPReply::bad_request, "invalid_request",
                                   CString().Format(value_error, "client_id"));
                        return;
                    }

                    const auto &provider = providers.DefaultValue();
                    Authorization.Username = provider.ClientId(WEB_APPLICATION_NAME);
                }

                if (Authorization.Password.IsEmpty()) {
                    CString Application;
                    const auto index = OAuth2::Helper::ProviderByClientId(providers, Authorization.Username, Application);
                    if (index != -1) {
                        const auto &provider = providers[index].Value();
                        if (Application == WEB_APPLICATION_NAME ||
                            Application == SERVICE_APPLICATION_NAME) { // TODO: Need delete application "service"

                            if (!redirect_uri.empty()) {
                                CStringList RedirectURI;
                                provider.RedirectURI(Application, RedirectURI);
                                if (RedirectURI.IndexOfName(redirect_uri) == -1) {
                                    ReplyError(AConnection, CHTTPReply::bad_request, "invalid_request",
                                               CString().Format(redirect_error, redirect_uri.c_str()));
                                    return;
                                }
                            }

                            CStringList JavaScriptOrigins;
                            provider.JavaScriptOrigins(Application, JavaScriptOrigins);
                            if (JavaScriptOrigins.IndexOfName(origin) == -1) {
                                ReplyError(AConnection, CHTTPReply::bad_request, "invalid_request",
                                           CString().Format(js_origin_error, origin.c_str()));
                                return;
                            }

                            Authorization.Password = provider.Secret(Application);
                        }
                    }
                }

                if (Authorization.Password.IsEmpty()) {
                    ReplyError(AConnection, CHTTPReply::bad_request, "invalid_request",
                               CString().Format(value_error, "client_secret"));
                    return;
                }
            }

            const auto &agent = GetUserAgent(AConnection);
            const auto &host = GetRealIP(AConnection);

            CStringList SQL;

            SQL.Add(CString().Format("SELECT * FROM daemon.token(%s, %s, '%s'::jsonb, %s, %s);",
                                     PQQuoteLiteral(Authorization.Username).c_str(),
                                     PQQuoteLiteral(Authorization.Password).c_str(),
                                     Json.ToString().c_str(),
                                     PQQuoteLiteral(agent).c_str(),
                                     PQQuoteLiteral(host).c_str()
            ));

            try {
                ExecSQL(SQL, AConnection, OnExecuted, OnException);
            } catch (Delphi::Exception::Exception &E) {
                ReplyError(AConnection, CHTTPReply::bad_request, "temporarily_unavailable", "Temporarily unavailable.");
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::Login(CHTTPServerConnection *AConnection, const CJSON &Token) {

            const auto &errorLocation = AConnection->Data()["redirect_error"];

            try {
                const auto &token_type = Token["token_type"].AsString();
                const auto &id_token = Token["id_token"].AsString();

                CAuthorization Authorization;

                try {
                    Authorization << (token_type + " " + id_token);

                    if (Authorization.Schema == CAuthorization::asBearer) {
                        Authorization.Token = VerifyToken(Authorization.Token);
                    }

                    const auto &agent = GetUserAgent(AConnection);
                    const auto &protocol = GetProtocol(AConnection);
                    const auto &host = GetRealIP(AConnection);
                    const auto &host_name = GetHost(AConnection);

                    CStringList SQL;

                    SQL.Add(CString().Format("SELECT * FROM daemon.login(%s, %s, %s, %s);",
                                             PQQuoteLiteral(Authorization.Token).c_str(),
                                             PQQuoteLiteral(agent).c_str(),
                                             PQQuoteLiteral(host).c_str(),
                                             PQQuoteLiteral(CString().Format("%s://%s", protocol.c_str(), host_name.c_str())).c_str()
                    ));

                    AConnection->Data().Values("authorized", "false");
                    AConnection->Data().Values("signature", "false");
                    AConnection->Data().Values("path", "/sign/in/token");

                    try {
                        ExecSQL(SQL, AConnection);
                    } catch (Delphi::Exception::Exception &E) {
                        RedirectError(AConnection, errorLocation, CHTTPReply::service_unavailable, "temporarily_unavailable", "Temporarily unavailable.");
                    }
                } catch (jwt::token_expired_exception &e) {
                    RedirectError(AConnection, errorLocation, CHTTPReply::forbidden, "invalid_token", e.what());
                } catch (jwt::token_verification_exception &e) {
                    RedirectError(AConnection, errorLocation, CHTTPReply::unauthorized, "invalid_token", e.what());
                } catch (CAuthorizationError &e) {
                    RedirectError(AConnection, errorLocation, CHTTPReply::unauthorized, "unauthorized_client", e.what());
                } catch (std::exception &e) {
                    RedirectError(AConnection, errorLocation, CHTTPReply::bad_request, "invalid_token", e.what());
                }
            } catch (Delphi::Exception::Exception &E) {
                RedirectError(AConnection, errorLocation, CHTTPReply::internal_server_error, "server_error", E.what());
                Log()->Error(APP_LOG_INFO, 0, "[Token] Message: %s", E.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::SetAuthorizationData(CHTTPServerConnection *AConnection, const CJSON &Payload) {

            auto &Reply = AConnection->Reply();

            const auto &session = Payload[_T("session")].AsString();
            if (!session.IsEmpty())
                Reply.SetCookie(_T("SID"), session.c_str(), _T("/"), 60 * SecsPerDay);

            CString Redirect = AConnection->Data()["redirect"];
            if (!Redirect.IsEmpty()) {

                const auto &access_token = Payload[_T("access_token")].AsString();
                const auto &refresh_token = Payload[_T("refresh_token")].AsString();
                const auto &token_type = Payload[_T("token_type")].AsString();
                const auto &expires_in = Payload[_T("expires_in")].AsString();
                const auto &state = Payload[_T("state")].AsString();

                Redirect << "#access_token=" << access_token;

                if (!refresh_token.IsEmpty())
                    Redirect << "&refresh_token=" << CHTTPServer::URLEncode(refresh_token);

                Redirect << "&token_type=" << token_type;
                Redirect << "&expires_in=" << expires_in;
                Redirect << "&session=" << session;

                if (!state.IsEmpty())
                    Redirect << "&state=" << CHTTPServer::URLEncode(state);

                AConnection->Data().Values("redirect", Redirect);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CAuthServer::CheckAuthorizationData(const CHTTPRequest &Request, CAuthorization &Authorization) {

            const auto &headers = Request.Headers;
            const auto &authorization = headers["Authorization"];

            if (authorization.IsEmpty()) {

                Authorization.Username = headers["Session"];
                Authorization.Password = headers["Secret"];

                if (Authorization.Username.IsEmpty() || Authorization.Password.IsEmpty())
                    return false;

                Authorization.Schema = CAuthorization::asBasic;
                Authorization.Type = CAuthorization::atSession;

            } else {
                Authorization << authorization;
            }

            return true;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::ParseString(const CString &String, const CStringList &Strings, CStringList &Valid, CStringList &Invalid) {
            Valid.Clear();
            Invalid.Clear();

            if (!String.IsEmpty()) {
                Valid.LineBreak(", ");
                Invalid.LineBreak(", ");

                CStringList Scopes;
                SplitColumns(String, Scopes, ' ');

                for (int i = 0; i < Scopes.Count(); i++) {
                    if (Strings.IndexOfName(Scopes[i]) == -1) {
                        Invalid.Add(Scopes[i]);
                    } else {
                        Valid.Add(Scopes[i]);
                    }
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::FetchAccessToken(CHTTPServerConnection *AConnection, const CProvider &Provider, const CString &Code) {

            auto OnRequestToken = [](CHTTPClient *Sender, CHTTPRequest &Request) {

                const auto &token_uri = Sender->Data()["token_uri"];
                const auto &code = Sender->Data()["code"];
                const auto &client_id = Sender->Data()["client_id"];
                const auto &client_secret = Sender->Data()["client_secret"];
                const auto &redirect_uri = Sender->Data()["redirect_uri"];
                const auto &grant_type = Sender->Data()["grant_type"];

                Request.Content = _T("client_id=");
                Request.Content << CHTTPServer::URLEncode(client_id);

                Request.Content << _T("&client_secret=");
                Request.Content << CHTTPServer::URLEncode(client_secret);

                Request.Content << _T("&grant_type=");
                Request.Content << grant_type;

                Request.Content << _T("&code=");
                Request.Content << CHTTPServer::URLEncode(code);

                Request.Content << _T("&redirect_uri=");
                Request.Content << CHTTPServer::URLEncode(redirect_uri);

                CHTTPRequest::Prepare(Request, _T("POST"), token_uri.c_str(), _T("application/x-www-form-urlencoded"));

                DebugRequest(Request);
            };

            auto OnReplyToken = [this, AConnection](CTCPConnection *Sender) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto &Reply = pConnection->Reply();

                DebugReply(Reply);

                pConnection->CloseConnection(true);

                if (!Assigned(AConnection))
                    return false;

                if (AConnection->ClosedGracefully())
                    return false;

                const CJSON Json(Reply.Content);

                if (Reply.Status == CHTTPReply::ok) {
                    if (AConnection->Data()["provider"] == "google") {
                        Login(AConnection, Json);
                    } else {
                        SetAuthorizationData(AConnection, Json);
                        Redirect(AConnection, AConnection->Data()["redirect"], true);
                    }
                } else {
                    const auto &redirect_error = AConnection->Data()["redirect_error"];

                    const auto &error = Json[_T("error")].AsString();
                    const auto &error_description = Json[_T("error_description")].AsString();

                    RedirectError(AConnection, redirect_error, Reply.Status, error, error_description);
                }

                return true;
            };

            auto OnException = [AConnection](CTCPConnection *Sender, const Delphi::Exception::Exception &E) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                DebugReply(pConnection->Reply());

                const auto &redirect_error = AConnection->Data()["redirect_error"];

                if (!AConnection->ClosedGracefully())
                    RedirectError(AConnection, redirect_error, CHTTPReply::internal_server_error, "server_error", E.what());

                Log()->Error(APP_LOG_ERR, 0, "[%s:%d] %s", pClient->Host().c_str(), pClient->Port(), E.what());
            };

            const auto &caRequest = AConnection->Request();

            const auto &redirect_error = AConnection->Data()["redirect_error"];
            const auto &caApplication = WEB_APPLICATION_NAME;

            CString TokenURI(Provider.TokenURI(caApplication));

            if (!TokenURI.IsEmpty()) {
                if (TokenURI.front() == '/') {
                    TokenURI = caRequest.Location.Origin() + TokenURI;
                }

                CLocation URI(TokenURI);

                auto pClient = GetClient(URI.hostname, URI.port);

                pClient->Data().Values("client_id", Provider.ClientId(caApplication));
                pClient->Data().Values("client_secret", Provider.Secret(caApplication));
                pClient->Data().Values("grant_type", "authorization_code");
                pClient->Data().Values("code", Code);
                pClient->Data().Values("redirect_uri", caRequest.Location.Origin() + caRequest.Location.pathname);
                pClient->Data().Values("token_uri", URI.pathname);

                pClient->OnRequest(OnRequestToken);
                pClient->OnExecute(OnReplyToken);
                pClient->OnException(OnException);

                pClient->AutoFree(true);
                pClient->Active(true);
            } else {
                RedirectError(AConnection, redirect_error, CHTTPReply::bad_request, "invalid_request", "Parameter \"token_uri\" not found in provider configuration.");
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::DoGet(CHTTPServerConnection *AConnection) {

            auto SetSearch = [](const CStringList &Search, CString &Location) {
                for (int i = 0; i < Search.Count(); ++i) {
                    if (i == 0) {
                        Location << "?";
                    } else {
                        Location << "&";
                    }
                    Location << Search.Strings(i);
                }
            };

            const auto &caRequest = AConnection->Request();
            auto &Reply = AConnection->Reply();

            Reply.ContentType = CHTTPReply::html;

            CStringList Routs;
            SplitColumns(caRequest.Location.pathname, Routs, '/');

            if (Routs.Count() < 2) {
                AConnection->SendStockReply(CHTTPReply::not_found);
                return;
            }

            const auto &siteConfig = GetSiteConfig(caRequest.Location.Host());

            const auto &redirect_identifier = siteConfig["oauth2.identifier"];
            const auto &redirect_secret = siteConfig["oauth2.secret"];
            const auto &redirect_callback = siteConfig["oauth2.callback"];
            const auto &redirect_error = siteConfig["oauth2.error"];
            const auto &redirect_debug = siteConfig["oauth2.debug"];

            CString oauthLocation;

            CStringList Search;
            CStringList Valid;
            CStringList Invalid;

            CStringList ResponseType;
            ResponseType.Add("code");
            ResponseType.Add("token");

            CStringList AccessType;
            AccessType.Add("online");
            AccessType.Add("offline");

            CStringList Prompt;
            Prompt.Add("none");
            Prompt.Add("signin");
            Prompt.Add("secret");
            Prompt.Add("consent");
            Prompt.Add("select_account");

            const auto &providers = Server().Providers();
            const auto &action = Routs[1].Lower();

            if (action == "authorize" || action == "auth") {

                const auto &response_type = caRequest.Params["response_type"];
                const auto &client_id = caRequest.Params["client_id"];
                const auto &access_type = caRequest.Params["access_type"];
                const auto &redirect_uri = caRequest.Params["redirect_uri"];
                const auto &scope = caRequest.Params["scope"];
                const auto &state = caRequest.Params["state"];
                const auto &prompt = caRequest.Params["prompt"];

                if (redirect_uri.IsEmpty()) {
                    RedirectError(AConnection, redirect_error, CHTTPReply::bad_request, "invalid_request",
                                  CString().Format("Parameter value redirect_uri cannot be empty."));
                    return;
                }

                CString Application;

                const auto index = OAuth2::Helper::ProviderByClientId(providers, client_id, Application);
                if (index == -1) {
                    RedirectError(AConnection, redirect_error, CHTTPReply::unauthorized, "invalid_client", CString().Format("The OAuth client was not found."));
                    return;
                }

                const auto& provider = providers[index].Value();

                CStringList RedirectURI;
                provider.RedirectURI(Application, RedirectURI);
                if (RedirectURI.IndexOfName(redirect_uri) == -1) {
                    RedirectError(AConnection, redirect_error, CHTTPReply::bad_request, "invalid_request",
                                  CString().Format("Invalid parameter value for redirect_uri: Non-public domains not allowed: %s", redirect_uri.c_str()));
                    return;
                }

                ParseString(response_type, ResponseType, Valid, Invalid);

                if (Invalid.Count() > 0) {
                    RedirectError(AConnection, redirect_error, CHTTPReply::bad_request, "unsupported_response_type",
                                  CString().Format("Some requested response type were invalid: {valid=[%s], invalid=[%s]}",
                                                   Valid.Text().c_str(), Invalid.Text().c_str()));
                    return;
                }

                if (response_type == "token")
                    AccessType.Clear();

                if (!access_type.IsEmpty() && AccessType.IndexOfName(access_type) == -1) {
                    RedirectError(AConnection, redirect_error, CHTTPReply::bad_request, "invalid_request",
                                  CString().Format("Invalid access_type: %s", access_type.c_str()));
                    return;
                }

                CStringList Scopes;
                provider.GetScopes(Application, Scopes);
                ParseString(scope, Scopes, Valid, Invalid);

                if (Invalid.Count() > 0) {
                    RedirectError(AConnection, redirect_error, CHTTPReply::bad_request, "invalid_scope",
                                  CString().Format("Some requested scopes were invalid: {valid=[%s], invalid=[%s]}",
                                                   Valid.Text().c_str(), Invalid.Text().c_str()));
                    return;
                }

                ParseString(prompt, Prompt, Valid, Invalid);

                if (Invalid.Count() > 0) {
                    RedirectError(AConnection, redirect_error, CHTTPReply::bad_request, "unsupported_prompt_type",
                                  CString().Format("Some requested prompt type were invalid: {valid=[%s], invalid=[%s]}",
                                                   Valid.Text().c_str(), Invalid.Text().c_str()));
                    return;
                }

                oauthLocation = prompt == "secret" ? redirect_secret : redirect_identifier;

                Search.Clear();

                Search.AddPair("client_id", client_id);
                Search.AddPair("response_type", response_type);

                if (!redirect_uri.IsEmpty())
                    Search.AddPair("redirect_uri", CHTTPServer::URLEncode(redirect_uri));
                if (!access_type.IsEmpty())
                    Search.AddPair("access_type", access_type);
                if (!scope.IsEmpty())
                    Search.AddPair("scope", CHTTPServer::URLEncode(scope));
                if (!prompt.IsEmpty())
                    Search.AddPair("prompt", CHTTPServer::URLEncode(prompt));
                if (!state.IsEmpty())
                    Search.AddPair("state", CHTTPServer::URLEncode(state));

                SetSearch(Search, oauthLocation);

            } else if (action == "code") {

                const auto &error = caRequest.Params["error"];

                if (!error.IsEmpty()) {
                    const auto ErrorCode = StrToIntDef(caRequest.Params["code"].c_str(), CHTTPReply::bad_request);
                    RedirectError(AConnection, redirect_error, (int) ErrorCode, error, caRequest.Params["error_description"]);
                    return;
                }

                const auto &code = caRequest.Params["code"];
                const auto &state = caRequest.Params["state"];

                if (!code.IsEmpty()) {
                    const auto &providerName = Routs.Count() == 3 ? Routs[2].Lower() : "default";
                    const auto &provider = providers[providerName];

                    AConnection->Data().Values("provider", providerName);
                    AConnection->Data().Values("redirect", state == "debug" ? redirect_debug : redirect_callback);
                    AConnection->Data().Values("redirect_error", redirect_error);

                    FetchAccessToken(AConnection, provider, code);
                } else {
                    RedirectError(AConnection, redirect_error, CHTTPReply::bad_request, "invalid_request", "Parameter \"code\" not found.");
                }

                return;

            } else if (action == "callback") {

                oauthLocation = redirect_callback;

            } else if (action == "identifier") {
                DoIdentifier(AConnection);
                return;
            }

            if (oauthLocation.IsEmpty())
                AConnection->SendStockReply(CHTTPReply::not_found);
            else
                Redirect(AConnection, oauthLocation);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::DoPost(CHTTPServerConnection *AConnection) {

            const auto &caRequest = AConnection->Request();
            auto &Reply = AConnection->Reply();

            Reply.ContentType = CHTTPReply::json;

            CStringList Routs;
            SplitColumns(caRequest.Location.pathname, Routs, '/');

            if (Routs.Count() < 2) {
                ReplyError(AConnection, CHTTPReply::not_found, "invalid_request", "Not found.");
                return;
            }

            AConnection->Data().Values("oauth2", "true");
            AConnection->Data().Values("path", caRequest.Location.pathname);

            try {
                const auto &action = Routs[1].Lower();

                if (action == "token") {
                    DoToken(AConnection);
                } else if (action == "identifier") {
                    DoIdentifier(AConnection);
                } else {
                    ReplyError(AConnection, CHTTPReply::not_found, "invalid_request", "Not found.");
                }
            } catch (Delphi::Exception::Exception &E) {
                ReplyError(AConnection, CHTTPReply::bad_request, "invalid_request", E.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::FetchCerts(CProvider &Provider) {

            const auto& URI = Provider.CertURI(WEB_APPLICATION_NAME);

            if (URI.IsEmpty()) {
                Log()->Error(APP_LOG_INFO, 0, _T("Certificate URI in provider \"%s\" is empty."), Provider.Name().c_str());
                return;
            }

            Log()->Error(APP_LOG_INFO, 0, _T("Trying to fetch public keys from: %s"), URI.c_str());

            auto OnRequest = [&Provider](CHTTPClient *Sender, CHTTPRequest &Request) {
                Provider.KeyStatusTime(Now());
                Provider.KeyStatus(ksFetching);
                CLocation Location(Provider.CertURI(WEB_APPLICATION_NAME));
                CHTTPRequest::Prepare(Request, "GET", Location.pathname.c_str());
            };

            auto OnExecute = [&Provider](CTCPConnection *AConnection) {
                auto pConnection = dynamic_cast<CHTTPClientConnection *> (AConnection);
                auto &Reply = pConnection->Reply();

                try {
                    DebugRequest(pConnection->Request());
                    DebugReply(Reply);

                    if (Reply.Status == CHTTPReply::ok) {
                        Provider.Keys().Clear();
                        Provider.Keys() << Reply.Content;
                        Provider.KeyStatusTime(Now());
                        Provider.KeyStatus(ksSuccess);
                    } else {
                        Provider.KeyStatusTime(Now());
                        Provider.KeyStatus(ksFailed);
                        Log()->Error(APP_LOG_ERR, 0, "[Certificate] Status: %d (%s)", Reply.Status, Reply.StatusText.c_str());
                    }
                } catch (Delphi::Exception::Exception &E) {
                    Provider.KeyStatusTime(Now());
                    Provider.KeyStatus(ksFailed);
                    Log()->Error(APP_LOG_ERR, 0, "[Certificate] Message: %s", E.what());
                }

                pConnection->CloseConnection(true);
                return true;
            };

            auto OnException = [this, &Provider](CTCPConnection *AConnection, const Delphi::Exception::Exception &E) {
                auto pConnection = dynamic_cast<CHTTPClientConnection *> (AConnection);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                Provider.KeyStatusTime(Now());
                Provider.KeyStatus(ksFailed);

                m_FixedDate = Now() + (CDateTime) 5 / SecsPerDay; // 5 sec

                Log()->Error(APP_LOG_ERR, 0, "[%s:%d] %s", pClient->Host().c_str(), pClient->Port(), E.what());
            };

            CLocation Location(URI);
            auto pClient = GetClient(Location.hostname, Location.port);

            pClient->OnRequest(OnRequest);
            pClient->OnExecute(OnExecute);
            pClient->OnException(OnException);

            pClient->AutoFree(true);
            pClient->Active(true);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::FetchProviders() {
            auto& Providers = Server().Providers();
            for (int i = 0; i < Providers.Count(); i++) {
                auto& Provider = Providers[i].Value();
                if (Provider.ApplicationExists(WEB_APPLICATION_NAME)) {
                    if (Provider.KeyStatus() == ksUnknown) {
                        FetchCerts(Provider);
                    }
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::CheckProviders() {
            auto& Providers = Server().Providers();
            for (int i = 0; i < Providers.Count(); i++) {
                auto& Provider = Providers[i].Value();
                if (Provider.ApplicationExists(WEB_APPLICATION_NAME)) {
                    if (Provider.KeyStatus() != ksUnknown) {
                        Provider.KeyStatusTime(Now());
                        Provider.KeyStatus(ksUnknown);
                    }
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::Heartbeat(CDateTime DateTime) {
            if ((DateTime >= m_FixedDate)) {
                m_FixedDate = DateTime + (CDateTime) 30 / MinsPerDay; // 30 min

                CheckProviders();
                FetchProviders();
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CAuthServer::Enabled() {
            if (m_ModuleStatus == msUnknown)
                m_ModuleStatus = Config()->IniFile().ReadBool(SectionName(), "enable", true) ? msEnabled : msDisabled;
            return m_ModuleStatus == msEnabled;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CAuthServer::CheckLocation(const CLocation &Location) {
            return Location.pathname.SubString(0, 8) == _T("/oauth2/");
        }
        //--------------------------------------------------------------------------------------------------------------
    }
}
}