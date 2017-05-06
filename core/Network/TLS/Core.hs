{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}
-- |
-- Module      : Network.TLS.Core
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Core
    (
    -- * Internal packet sending and receiving
      sendPacket
    , recvPacket

    -- * Initialisation and Termination of context
    , bye
    , handshake

    -- * Application Layer Protocol Negotiation
    , getNegotiatedProtocol

    -- * Server Name Indication
    , getClientSNI

    -- * High level API
    , sendData
    , recvData
    , recvData'
    ) where

import Network.TLS.Context
import Network.TLS.Struct
import Network.TLS.State (getSession)
import Network.TLS.Parameters
import Network.TLS.IO
import Network.TLS.Session
import Network.TLS.Handshake
import Network.TLS.ErrT
import Network.TLS.Util (catchException)
import qualified Network.TLS.State as S
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()
import qualified Data.ByteString.Lazy as L

import Control.Monad.State.Strict


-- | notify the context that this side wants to close connection.
-- this is important that it is called before closing the handle, otherwise
-- the session might not be resumable (for version < TLS1.2).
--
-- This doesn't actually close the handle. If it fails, it does so silently,
bye :: MonadIO m => Context -> m ()
bye ctx = void . sendPacket ctx $ Alert [(AlertLevel_Warning, CloseNotify)]

-- | If the ALPN extensions have been used, this will
-- return get the protocol agreed upon.
getNegotiatedProtocol :: MonadIO m => Context -> m (Maybe B.ByteString)
getNegotiatedProtocol ctx =
    either (const $ pure Nothing) pure =<< liftIO (runErrT $ usingStateT ctx S.getNegotiatedProtocol)

type HostName = String

-- | If the Server Name Indication extension has been used, return the
-- hostname specified by the client.
getClientSNI :: MonadIO m => Context -> m (Maybe HostName)
getClientSNI ctx =
    either (const $ pure Nothing) pure =<< liftIO (runErrT $ usingStateT ctx S.getClientSNI)


-- | sendData sends a bunch of data.
-- It will automatically chunk data to acceptable packet size
sendData :: MonadIO m => Context -> L.ByteString -> m (Either TLSError ())
sendData ctx dataToSend = liftIO . runErrT $ do
    checkValidT ctx
    mapM_ sendDataChunk (L.toChunks dataToSend)
  where sendDataChunk d
            | B.length d > 16384 = do
                let (sending, remain) = B.splitAt 16384 d
                sendPacketT ctx $ AppData sending
                sendDataChunk remain
            | otherwise = sendPacket ctx $ AppData d

-- | recvData get data out of Data packet, and automatically renegotiate if
-- a Handshake ClientHello is received
recvData :: MonadIO m => Context -> m (Either TLSError B.ByteString)
recvData = liftIO . runErrT . recvDataT

recvDataT :: Context -> ErrT TLSError IO B.ByteString
recvDataT ctx = do
    checkValidT ctx
    pkt <- withReadLockT ctx $ recvPacket ctx
    either onError process pkt
  where onError Error_EOF = -- Not really an error.
            return B.empty

        onError err@(Error_Protocol (reason,fatal,desc)) =
            terminate err (if fatal then AlertLevel_Fatal else AlertLevel_Warning) desc reason
        onError err =
            terminate err AlertLevel_Fatal InternalError (show err)

        process (Handshake [ch@ClientHello {}]) =
            withRWLockT ctx (ctxDoHandshakeWith ctx ctx ch) >> recvDataT ctx
        process (Handshake [hr@HelloRequest]) =
            withRWLockT ctx (ctxDoHandshakeWith ctx ctx hr) >> recvDataT ctx

        process (Alert [(AlertLevel_Warning, CloseNotify)]) = liftIO (tryBye >> setEOF ctx >> return B.empty)
        process (Alert [(AlertLevel_Fatal, desc)]) = do
            liftIO $ setEOF ctx
            left $ Error_Exception (Terminated True ("received fatal error: " ++ show desc) (Error_Protocol ("remote side fatal error", True, desc)))

        -- when receiving empty appdata, we just retry to get some data.
        process (AppData "") = recvDataT ctx
        process (AppData x)  = return x
        process p            = let reason = "unexpected message " ++ show p in
                               terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason

        terminate :: TLSError -> AlertLevel -> AlertDescription -> String -> ErrT TLSError IO a
        terminate err level desc reason = do
            session <- usingStateT ctx getSession
            liftIO $ do
                case session of
                    Session Nothing    -> return ()
                    Session (Just sid) -> sessionInvalidate (sharedSessionManager $ ctxShared ctx) sid
                catchException (void . sendPacket ctx $ Alert [(level, desc)]) (\_ -> return ())
                setEOF ctx
            left $ Error_Exception (Terminated False reason err)

        -- the other side could have close the connection already, so wrap
        -- this in a try and ignore all exceptions
        tryBye = catchException (bye ctx) (\_ -> return ())

{-# DEPRECATED recvData' "use recvData that returns strict bytestring" #-}
-- | same as recvData but returns a lazy bytestring.
recvData' :: MonadIO m => Context -> m (Either TLSError L.ByteString)
recvData' ctx =
    fmap (\bs -> L.fromChunks [bs]) <$> recvData ctx
