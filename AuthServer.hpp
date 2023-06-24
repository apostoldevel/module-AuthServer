/*++

Program name:

  Apostol CRM

Module Name:

  AuthServer.hpp

Notices:

  Module: OAuth 2 Authorization Server

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

#ifndef APOSTOL_AUTHSERVER_HPP
#define APOSTOL_AUTHSERVER_HPP
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Module {

        //--------------------------------------------------------------------------------------------------------------

        //-- CAuthServer -----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CAuthServer: public CApostolModule {
        private:

            CDateTime m_FixedDate;

            void InitMethods() override;

            void FetchAccessToken(CHTTPServerConnection *AConnection, const CProvider &Provider, const CString& Code);

            void FetchCerts(CProvider &Provider);

            void FetchProviders();
            void CheckProviders();

            static void AfterQuery(CHTTPServerConnection *AConnection, const CString &Path, const CJSON &Payload);

            static void QueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E);

            CString CreateToken(const CCleanToken& CleanToken);
            CString VerifyToken(const CString &Token);

            static void ParseString(const CString &String, const CStringList &Strings, CStringList &Valid, CStringList &Invalid);

            static bool CheckAuthorizationData(const CHTTPRequest &Request, CAuthorization &Authorization);

            static int CheckOAuth2Error(const CJSON &Json, CString &Error, CString &ErrorDescription);
            static int CheckError(const CJSON &Json, CString &ErrorMessage, bool RaiseIfError = false);

            static CHTTPReply::CStatusType ErrorCodeToStatus(int ErrorCode);

            static void RedirectError(CHTTPServerConnection *AConnection, const CString &Location, int ErrorCode, const CString &Error, const CString &Message);
            static void ReplyError(CHTTPServerConnection *AConnection, int ErrorCode, const CString &Error, const CString &Message);

            static void SetAuthorizationData(CHTTPServerConnection *AConnection, const CJSON &Payload);
            static void SetSecure(CHTTPReply &Reply, const CString &AccessToken, const CString &RefreshToken, const CString &Session, const CString &Domain);

            void Login(CHTTPServerConnection *AConnection, const CJSON &Token);

        protected:

            void DoGet(CHTTPServerConnection *AConnection) override;
            void DoPost(CHTTPServerConnection *AConnection);

            void DoToken(CHTTPServerConnection *AConnection);
            void DoIdentifier(CHTTPServerConnection *AConnection);

            void DoPostgresQueryExecuted(CPQPollQuery *APollQuery) override;
            void DoPostgresQueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) override;

        public:

            explicit CAuthServer(CModuleProcess *AProcess);

            ~CAuthServer() override = default;

            static class CAuthServer *CreateModule(CModuleProcess *AProcess) {
                return new CAuthServer(AProcess);
            }

            bool CheckAuthorization(CHTTPServerConnection *AConnection, CAuthorization &Authorization);

            void Heartbeat(CDateTime DateTime) override;

            bool Enabled() override;

            bool CheckLocation(const CLocation &Location) override;

        };
    }
}

using namespace Apostol::Module;
}
#endif //APOSTOL_AUTHSERVER_HPP
