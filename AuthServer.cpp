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

#define PROVIDER_APPLICATION_NAME "web"

extern "C++" {

namespace Apostol {

    namespace Workers {

        //--------------------------------------------------------------------------------------------------------------

        //-- CAuthServer -----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        CAuthServer::CAuthServer(CModuleProcess *AProcess) : CApostolModule(AProcess,
                "authorization server", "worker/AuthServer") {

            m_Headers.Add("Authorization");
            m_FixedDate = Now();

            CAuthServer::InitMethods();
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::InitMethods() {
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            m_pMethods->AddObject(_T("GET")    , (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoGet(Connection); }));
            m_pMethods->AddObject(_T("POST")   , (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoPost(Connection); }));
            m_pMethods->AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoOptions(Connection); }));
            m_pMethods->AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
#else
            m_pMethods->AddObject(_T("GET")    , (CObject *) new CMethodHandler(true , std::bind(&CAuthServer::DoGet, this, _1)));
            m_pMethods->AddObject(_T("POST")   , (CObject *) new CMethodHandler(true , std::bind(&CAuthServer::DoPost, this, _1)));
            m_pMethods->AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(true , std::bind(&CAuthServer::DoOptions, this, _1)));
            m_pMethods->AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, std::bind(&CAuthServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, std::bind(&CAuthServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, std::bind(&CAuthServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, std::bind(&CAuthServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, std::bind(&CAuthServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, std::bind(&CAuthServer::MethodNotAllowed, this, _1)));
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

            auto pConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->PollConnection());

            if (pConnection != nullptr && !pConnection->ClosedGracefully()) {

                const auto& Path = pConnection->Data()["path"].Lower();

                auto pRequest = pConnection->Request();
                auto pReply = pConnection->Reply();

                const auto& result_object = pRequest->Params[_T("result_object")];
                const auto& data_array = pRequest->Params[_T("data_array")];

                CHTTPReply::CStatusType LStatus = CHTTPReply::ok;

                try {
                    if (pResult->nTuples() == 1) {
                        const CJSON Payload(pResult->GetValue(0, 0));
                        LStatus = ErrorCodeToStatus(CheckError(Payload, ErrorMessage));
                        if (LStatus == CHTTPReply::ok) {
                            AfterQuery(pConnection, Path, Payload);
                        }
                    }

                    PQResultToJson(pResult, pReply->Content);
                } catch (Delphi::Exception::Exception &E) {
                    ErrorMessage = E.what();
                    LStatus = CHTTPReply::bad_request;
                    Log()->Error(APP_LOG_EMERG, 0, E.what());
                }

                const auto& LRedirect = LStatus == CHTTPReply::ok ? pConnection->Data()["redirect"] : pConnection->Data()["redirect_error"];

                if (LRedirect.IsEmpty()) {
                    if (LStatus == CHTTPReply::ok) {
                        pConnection->SendReply(LStatus, nullptr, true);
                    } else {
                        ReplyError(pConnection, LStatus, "server_error", ErrorMessage);
                    }
                } else {
                    if (LStatus == CHTTPReply::ok) {
                        Redirect(pConnection, LRedirect, true);
                    } else {
                        switch (LStatus) {
                            case CHTTPReply::unauthorized:
                                RedirectError(pConnection, LRedirect, LStatus, "unauthorized_client", ErrorMessage);
                                break;

                            case CHTTPReply::forbidden:
                                RedirectError(pConnection, LRedirect, LStatus, "access_denied", ErrorMessage);
                                break;

                            case CHTTPReply::internal_server_error:
                                RedirectError(pConnection, LRedirect, LStatus, "server_error", ErrorMessage);
                                break;

                            default:
                                RedirectError(pConnection, LRedirect, LStatus, "invalid_request", ErrorMessage);
                                break;
                        }
                    }
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::QueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {

            auto pConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->PollConnection());

            if (pConnection != nullptr && !pConnection->ClosedGracefully()) {
                auto pReply = pConnection->Reply();

                const auto& LRedirect = pConnection->Data()["redirect_error"];

                if (!LRedirect.IsEmpty()) {
                    RedirectError(pConnection, LRedirect, CHTTPReply::internal_server_error, "server_error", E.what());
                } else {
                    ExceptionToJson(CHTTPReply::internal_server_error, E, pReply->Content);
                    pConnection->SendReply(CHTTPReply::ok, nullptr, true);
                }
            }

            Log()->Error(APP_LOG_EMERG, 0, E.what());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::DoPostgresQueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
            QueryException(APollQuery, E);
        }
        //--------------------------------------------------------------------------------------------------------------

        CString CAuthServer::CreateToken(const CCleanToken& CleanToken) {
            const auto& Providers = Server().Providers();
            const auto& Default = Providers.Default().Value();
            const CString Application(PROVIDER_APPLICATION_NAME);
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
                    throw ExceptionFrm("Not found Secret for \"%s:%s\"",
                                       Provider.Name.c_str(),
                                       Application.c_str()
                    );
                return Secret;
            };

            auto decoded = jwt::decode(Token);
            const auto& aud = CString(decoded.get_audience());

            CString Application;

            const auto& Providers = Server().Providers();

            const auto Index = OAuth2::Helper::ProviderByClientId(Providers, aud, Application);
            if (Index == -1)
                throw COAuth2Error(_T("Not found provider by Client ID."));

            const auto& Provider = Providers[Index].Value();

            const auto& iss = CString(decoded.get_issuer());

            CStringList Issuers;
            Provider.GetIssuers(Application, Issuers);
            if (Issuers[iss].IsEmpty())
                throw jwt::token_verification_exception("Token doesn't contain the required issuer.");

            const auto& alg = decoded.get_algorithm();
            const auto& ch = alg.substr(0, 2);

            const auto& Secret = GetSecret(Provider, Application);

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

            auto pRequest = AConnection->Request();

            try {
                if (CheckAuthorizationData(pRequest, Authorization)) {
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

                auto pReply = AConnection->Reply();
                auto pResult = APollQuery->Results(0);

                CString errorMessage;
                CHTTPReply::CStatusType LStatus = CHTTPReply::internal_server_error;

                try {
                    if (pResult->ExecStatus() != PGRES_TUPLES_OK)
                        throw Delphi::Exception::EDBError(pResult->GetErrorMessage());

                    pReply->ContentType = CHTTPReply::json;

                    const CJSON Payload(pResult->GetValue(0, 0));
                    LStatus = ErrorCodeToStatus(CheckError(Payload, errorMessage));
                    PQResultToJson(pResult, pReply->Content);
                } catch (Delphi::Exception::Exception &E) {
                    pReply->Content.Clear();
                    ExceptionToJson(LStatus, E, pReply->Content);
                    Log()->Error(APP_LOG_EMERG, 0, E.what());
                }

                AConnection->SendReply(LStatus, nullptr, true);
            };

            auto OnException = [AConnection](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                ReplyError(AConnection, CHTTPReply::internal_server_error, "server_error", E.what());
            };

            auto pRequest = AConnection->Request();

            CJSON Json;
            ContentToJson(pRequest, Json);

            const auto &Identifier = Json["value"].AsString();

            if (Identifier.IsEmpty()) {
                ReplyError(AConnection, CHTTPReply::bad_request, "invalid_request", "Invalid request.");
                return;
            }

            CAuthorization Authorization;
            if (!CheckAuthorization(AConnection, Authorization))
                return;

            CStringList SQL;

            SQL.Add(CString().Format("SELECT * FROM daemon.identifier(%s);", PQQuoteLiteral(Identifier).c_str()));

            try {
                ExecSQL(SQL, nullptr, OnExecuted, OnException);
            } catch (Delphi::Exception::Exception &E) {
                ReplyError(AConnection, CHTTPReply::service_unavailable, "temporarily_unavailable", "Temporarily unavailable.");
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::RedirectError(CHTTPServerConnection *AConnection, const CString &Location, int ErrorCode, const CString &Error, const CString &Message) {
            CString errorLocation(Location);

            errorLocation << "?code=" << ErrorCode;
            errorLocation << "&error=" << Error;
            errorLocation << "&error_description=" << CHTTPServer::URLEncode(Message);

            Redirect(AConnection, errorLocation, true);

            Log()->Error(APP_LOG_EMERG, 0, _T("RedirectError: %s"), Message.c_str());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::ReplyError(CHTTPServerConnection *AConnection, int ErrorCode, const CString &Error, const CString &Message) {
            auto pReply = AConnection->Reply();

            pReply->ContentType = CHTTPReply::json;

            CHTTPReply::CStatusType Status = ErrorCodeToStatus(ErrorCode);

            if (ErrorCode == CHTTPReply::unauthorized) {
                CHTTPReply::AddUnauthorized(pReply, true, "access_denied", Message.c_str());
            }

            pReply->Content.Clear();
            pReply->Content.Format(R"({"error": "%s", "error_description": "%s"})",
                                   Error.c_str(), Delphi::Json::EncodeJsonString(Message).c_str());

            AConnection->SendReply(Status, nullptr, true);

            Log()->Error(APP_LOG_NOTICE, 0, _T("ReplyError: %s"), Message.c_str());
        };
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::DoToken(CHTTPServerConnection *AConnection) {

            auto OnExecuted = [AConnection](CPQPollQuery *APollQuery) {

                auto pReply = AConnection->Reply();
                auto pResult = APollQuery->Results(0);

                CString Error;
                CString ErrorDescription;

                CHTTPReply::CStatusType LStatus;

                try {
                    if (pResult->ExecStatus() != PGRES_TUPLES_OK)
                        throw Delphi::Exception::EDBError(pResult->GetErrorMessage());

                    PQResultToJson(pResult, pReply->Content);

                    const CJSON Json(pReply->Content);
                    LStatus = ErrorCodeToStatus(CheckOAuth2Error(Json, Error, ErrorDescription));

                    if (LStatus == CHTTPReply::ok) {
                        AConnection->SendReply(LStatus, nullptr, true);
                    } else {
                        ReplyError(AConnection, LStatus, Error, ErrorDescription);
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

            auto pRequest = AConnection->Request();
            auto pReply = AConnection->Reply();

            CJSON Json;
            ContentToJson(pRequest, Json);

            const auto &client_id = Json["client_id"].AsString();
            const auto &client_secret = Json["client_secret"].AsString();
            const auto &grant_type = Json["grant_type"].AsString();
            const auto &redirect_uri = Json["redirect_uri"].AsString();

            CString Application(PROVIDER_APPLICATION_NAME);
            const auto &Origin = GetOrigin(AConnection);

            CAuthorization Authorization;
            const auto &caAuthorization = pRequest->Headers.Values(_T("Authorization"));

            if (caAuthorization.IsEmpty()) {
                const auto &Providers = Server().Providers();

                Authorization.Schema = CAuthorization::asBasic;

                if (client_id.IsEmpty()) {
                    const auto &Provider = Providers.Default().Value();
                    Authorization.Username = Provider.ClientId(Application);
                } else {
                    Authorization.Username = client_id;
                }

                if (client_secret.IsEmpty()) {
                    const auto Index = OAuth2::Helper::ProviderByClientId(Providers, client_id, Application);
                    if (Index != -1) {
                        const auto &Provider = Providers[Index].Value();
                        if (Application == PROVIDER_APPLICATION_NAME || Application == "service") { // TODO: Need delete application "service"
                            if (!redirect_uri.IsEmpty()) {
                                CStringList RedirectURI;
                                Provider.RedirectURI(Application, RedirectURI);
                                if (RedirectURI.IndexOfName(redirect_uri) == -1) {
                                    ReplyError(AConnection, CHTTPReply::bad_request, "invalid_request",
                                               CString().Format(redirect_error, redirect_uri.c_str()));
                                    return;
                                }
                            } else {
                                CStringList JavaScriptOrigins;
                                Provider.JavaScriptOrigins(Application, JavaScriptOrigins);
                                if (JavaScriptOrigins.IndexOfName(Origin) == -1) {
                                    ReplyError(AConnection, CHTTPReply::bad_request, "invalid_request",
                                               CString().Format(js_origin_error, Origin.c_str()));
                                    return;
                                }
                            }
                            Authorization.Password = Provider.Secret(Application);
                        }
                    }
                } else {
                    Authorization.Password = client_secret;
                }
            } else {
                Authorization << caAuthorization;

                if (Authorization.Schema != CAuthorization::asBasic) {
                    ReplyError(AConnection, CHTTPReply::bad_request, "invalid_request", "Invalid authorization schema.");
                    return;
                }
            }

            if (Authorization.Password.IsEmpty()) {
                ReplyError(AConnection, CHTTPReply::bad_request, "invalid_request", CString().Format(value_error, "client_secret"));
                return;
            }

            const auto &caAgent = GetUserAgent(AConnection);
            const auto &caHost = GetHost(AConnection);

            CStringList SQL;

            SQL.Add(CString().Format("SELECT * FROM daemon.token(%s, %s, '%s'::jsonb, %s, %s);",
                                     PQQuoteLiteral(Authorization.Username).c_str(),
                                     PQQuoteLiteral(Authorization.Password).c_str(),
                                     Json.ToString().c_str(),
                                     PQQuoteLiteral(caAgent).c_str(),
                                     PQQuoteLiteral(caHost).c_str()
            ));

            try {
                ExecSQL(SQL, AConnection, OnExecuted, OnException);
            } catch (Delphi::Exception::Exception &E) {
                ReplyError(AConnection, CHTTPReply::bad_request, "temporarily_unavailable", "Temporarily unavailable.");
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::SignInToken(CHTTPServerConnection *AConnection, const CJSON &Token) {

            const auto &errorLocation = AConnection->Data()["redirect_error"];

            try {
                const auto &tokenType = Token["token_type"].AsString();
                const auto &idToken = Token["id_token"].AsString();

                CAuthorization Authorization;

                try {
                    Authorization << (tokenType + " " + idToken);

                    if (Authorization.Schema == CAuthorization::asBearer) {
                        Authorization.Token = VerifyToken(Authorization.Token);
                    }

                    const auto &caAgent = GetUserAgent(AConnection);
                    const auto &caHost = GetHost(AConnection);

                    CStringList SQL;

                    SQL.Add(CString().Format("SELECT * FROM daemon.signin(%s, %s, %s);",
                                             PQQuoteLiteral(Authorization.Token).c_str(),
                                             PQQuoteLiteral(caAgent).c_str(),
                                             PQQuoteLiteral(caHost).c_str()
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

            auto pReply = AConnection->Reply();

            const auto &session = Payload[_T("session")].AsString();
            if (!session.IsEmpty())
                pReply->SetCookie(_T("SID"), session.c_str(), _T("/"), 60 * SecsPerDay);

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

        bool CAuthServer::CheckAuthorizationData(CHTTPRequest *ARequest, CAuthorization &Authorization) {

            const auto &caHeaders = ARequest->Headers;
            const auto &caAuthorization = caHeaders.Values(_T("Authorization"));

            if (caAuthorization.IsEmpty()) {

                const auto &caSession = caHeaders.Values(_T("Session"));
                const auto &caSecret = caHeaders.Values(_T("Secret"));

                Authorization.Username = caSession;
                Authorization.Password = caSecret;

                if (Authorization.Username.IsEmpty() || Authorization.Password.IsEmpty())
                    return false;

                Authorization.Schema = CAuthorization::asBasic;
                Authorization.Type = CAuthorization::atSession;

            } else {
                Authorization << caAuthorization;
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

            auto OnRequestToken = [](CHTTPClient *Sender, CHTTPRequest *ARequest) {

                const auto &token_uri = Sender->Data()["token_uri"];
                const auto &code = Sender->Data()["code"];
                const auto &client_id = Sender->Data()["client_id"];
                const auto &client_secret = Sender->Data()["client_secret"];
                const auto &redirect_uri = Sender->Data()["redirect_uri"];
                const auto &grant_type = Sender->Data()["grant_type"];

                ARequest->Content = _T("client_id=");
                ARequest->Content << CHTTPServer::URLEncode(client_id);

                ARequest->Content << _T("&client_secret=");
                ARequest->Content << CHTTPServer::URLEncode(client_secret);

                ARequest->Content << _T("&grant_type=");
                ARequest->Content << grant_type;

                ARequest->Content << _T("&code=");
                ARequest->Content << CHTTPServer::URLEncode(code);

                ARequest->Content << _T("&redirect_uri=");
                ARequest->Content << CHTTPServer::URLEncode(redirect_uri);

                CHTTPRequest::Prepare(ARequest, _T("POST"), token_uri.c_str(), _T("application/x-www-form-urlencoded"));

                DebugRequest(ARequest);
            };

            auto OnReplyToken = [this, AConnection](CTCPConnection *Sender) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto pReply = pConnection->Reply();

                DebugReply(pReply);

                pConnection->CloseConnection(true);

                if (AConnection->ClosedGracefully())
                    return true;

                const CJSON Json(pReply->Content);

                if (pReply->Status == CHTTPReply::ok) {

                    const auto &provider = AConnection->Data()["provider"];

                    if (provider == "default") {
                        SetAuthorizationData(AConnection, Json);
                        // Set after call SetAuthorizationData()
                        const auto &Location = AConnection->Data()["redirect"];
                        Redirect(AConnection, Location, true);
                    } else {
                        SignInToken(AConnection, Json);
                    }
                } else {
                    const auto &redirect_error = AConnection->Data()["redirect_error"];

                    const auto &error = Json[_T("error")].AsString();
                    const auto &error_description = Json[_T("error_description")].AsString();

                    RedirectError(AConnection, redirect_error, pReply->Status, error, error_description);
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

                Log()->Error(APP_LOG_EMERG, 0, "[%s:%d] %s", pClient->Host().c_str(), pClient->Port(), E.what());
            };

            auto pRequest = AConnection->Request();

            const auto &redirect_error = AConnection->Data()["redirect_error"];
            const auto &Application = PROVIDER_APPLICATION_NAME;

            CString TokenURI(Provider.TokenURI(Application));

            if (!TokenURI.IsEmpty()) {
                if (TokenURI.front() == '/') {
                    TokenURI = pRequest->Location.Origin() + TokenURI;
                }

                CLocation URI(TokenURI);

                auto pClient = GetClient(URI.hostname, URI.port);

                pClient->Data().Values("client_id", Provider.ClientId(Application));
                pClient->Data().Values("client_secret", Provider.Secret(Application));
                pClient->Data().Values("grant_type", "authorization_code");
                pClient->Data().Values("code", Code);
                pClient->Data().Values("redirect_uri", pRequest->Location.Origin() + pRequest->Location.pathname);
                pClient->Data().Values("token_uri", URI.pathname);

                pClient->OnRequest(OnRequestToken);
                pClient->OnExecute(OnReplyToken);
                pClient->OnException(OnException);

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

            auto pRequest = AConnection->Request();
            auto pReply = AConnection->Reply();

            pReply->ContentType = CHTTPReply::html;

            CStringList cRouts;
            SplitColumns(pRequest->Location.pathname, cRouts, '/');

            if (cRouts.Count() < 2) {
                AConnection->SendStockReply(CHTTPReply::not_found);
                return;
            }

            const auto &SiteConfig = GetSiteConfig(pRequest->Location.Host());

            const auto &redirect_identifier = SiteConfig["oauth2.identifier"];
            const auto &redirect_callback = SiteConfig["oauth2.callback"];
            const auto &redirect_error = SiteConfig["oauth2.error"];

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
            Prompt.Add("consent");
            Prompt.Add("select_account");

            const auto &Providers = Server().Providers();

            const auto &Action = cRouts[1].Lower();

            if (Action == "authorize" || Action == "auth") {

                const auto &response_type = pRequest->Params["response_type"];
                const auto &client_id = pRequest->Params["client_id"];
                const auto &access_type = pRequest->Params["access_type"];
                const auto &redirect_uri = pRequest->Params["redirect_uri"];
                const auto &scope = pRequest->Params["scope"];
                const auto &state = pRequest->Params["state"];
                const auto &prompt = pRequest->Params["prompt"];

                if (redirect_uri.IsEmpty()) {
                    RedirectError(AConnection, redirect_error, CHTTPReply::bad_request, "invalid_request",
                                  CString().Format("Parameter value redirect_uri cannot be empty."));
                    return;
                }

                const auto &Provider = Providers.Default().Value();

                CStringList clients;
                Provider.GetClients(clients);
                const auto &Application = clients[client_id];

                if (Application.IsEmpty()) {
                    RedirectError(AConnection, redirect_error, CHTTPReply::unauthorized, "invalid_client", CString().Format("The OAuth client was not found."));
                    return;
                }

                CStringList redirectURIs;
                Provider.RedirectURI(Application, redirectURIs);
                if (redirectURIs.IndexOfName(redirect_uri) == -1) {
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
                Provider.GetScopes(Application, Scopes);
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

                oauthLocation = redirect_identifier;

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

            } else if (Action == "code") {

                const auto &error = pRequest->Params["error"];

                if (!error.IsEmpty()) {
                    const auto ErrorCode = StrToIntDef(pRequest->Params["code"].c_str(), CHTTPReply::bad_request);
                    RedirectError(AConnection, redirect_error, ErrorCode, error, pRequest->Params["error_description"]);
                    return;
                }

                const auto &code = pRequest->Params["code"];
                const auto &state = pRequest->Params["state"];

                if (!code.IsEmpty()) {
                    const auto &providerName = cRouts.Count() == 3 ? cRouts[2].Lower() : "default";
                    const auto &Provider = Providers[providerName];

                    AConnection->Data().Values("provider", providerName);
                    AConnection->Data().Values("redirect", redirect_callback);
                    AConnection->Data().Values("redirect_error", redirect_error);

                    FetchAccessToken(AConnection, Provider, code);
                } else {
                    RedirectError(AConnection, redirect_error, CHTTPReply::bad_request, "invalid_request", "Parameter \"code\" not found.");
                }

                return;

            } else if (Action == "callback") {

                oauthLocation = redirect_callback;

            } else if (Action == "identifier") {
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

            auto pRequest = AConnection->Request();
            auto pReply = AConnection->Reply();

            pReply->ContentType = CHTTPReply::json;

            CStringList cRouts;
            SplitColumns(pRequest->Location.pathname, cRouts, '/');

            if (cRouts.Count() < 2) {
                ReplyError(AConnection, CHTTPReply::not_found, "invalid_request", "Not found.");
                return;
            }

            AConnection->Data().Values("oauth2", "true");
            AConnection->Data().Values("path", pRequest->Location.pathname);

            try {
                const auto &caAction = cRouts[1].Lower();

                if (caAction == "token") {
                    DoToken(AConnection);
                } else if (caAction == "identifier") {
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

            const auto& URI = Provider.CertURI(PROVIDER_APPLICATION_NAME);

            if (URI.IsEmpty()) {
                Log()->Error(APP_LOG_INFO, 0, _T("Certificate URI in provider \"%s\" is empty."), Provider.Name.c_str());
                return;
            }

            Log()->Error(APP_LOG_INFO, 0, _T("Trying to fetch public keys from: %s"), URI.c_str());

            auto OnRequest = [&Provider](CHTTPClient *Sender, CHTTPRequest *Request) {
                Provider.KeyStatusTime = Now();
                Provider.KeyStatus = CProvider::ksFetching;
                CLocation Location(Provider.CertURI(PROVIDER_APPLICATION_NAME));
                CHTTPRequest::Prepare(Request, "GET", Location.pathname.c_str());
            };

            auto OnExecute = [&Provider](CTCPConnection *AConnection) {
                auto pConnection = dynamic_cast<CHTTPClientConnection *> (AConnection);
                auto pReply = pConnection->Reply();

                try {
                    DebugRequest(pConnection->Request());
                    DebugReply(pReply);

                    Provider.KeyStatusTime = Now();

                    Provider.Keys.Clear();
                    Provider.Keys << pReply->Content;

                    Provider.KeyStatus = CProvider::ksSuccess;
                } catch (Delphi::Exception::Exception &E) {
                    Provider.KeyStatus = CProvider::ksFailed;
                    Log()->Error(APP_LOG_EMERG, 0, "[Certificate] Message: %s", E.what());
                }

                pConnection->CloseConnection(true);
                return true;
            };

            auto OnException = [&Provider](CTCPConnection *AConnection, const Delphi::Exception::Exception &E) {
                auto pConnection = dynamic_cast<CHTTPClientConnection *> (AConnection);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                Provider.KeyStatusTime = Now();
                Provider.KeyStatus = CProvider::ksFailed;

                Log()->Error(APP_LOG_EMERG, 0, "[%s:%d] %s", pClient->Host().c_str(), pClient->Port(), E.what());
            };

            CLocation Location(URI);
            auto pClient = GetClient(Location.hostname, Location.port);

            pClient->OnRequest(OnRequest);
            pClient->OnExecute(OnExecute);
            pClient->OnException(OnException);

            pClient->Active(true);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::FetchProviders() {
            auto& Providers = Server().Providers();
            for (int i = 0; i < Providers.Count(); i++) {
                auto& Provider = Providers[i].Value();
                if (Provider.ApplicationExists(PROVIDER_APPLICATION_NAME)) {
                    if (Provider.KeyStatus == CProvider::ksUnknown) {
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
                if (Provider.ApplicationExists(PROVIDER_APPLICATION_NAME)) {
                    if (Provider.KeyStatus != CProvider::ksUnknown) {
                        Provider.KeyStatusTime = Now();
                        Provider.KeyStatus = CProvider::ksUnknown;
                    }
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::Heartbeat() {
            auto now = Now();

            if ((now >= m_FixedDate)) {
                m_FixedDate = now + (CDateTime) 15 * 60 / SecsPerDay; // 15 min

                CheckProviders();
                FetchProviders();
            }

            m_pModuleProcess->ClientManager().CleanUp();
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