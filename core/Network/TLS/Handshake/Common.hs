{-# LANGUAGE OverloadedStrings #-}
module Network.TLS.Handshake.Common
    ( errorToAlert
    , unexpected
    , newSession
    , handshakeTerminate
    -- * sending packets
    , sendChangeCipherAndFinish
    -- * receiving packets
    , recvChangeCipherAndFinish
    , RecvState(..)
    , runRecvState
    , recvPacketHandshake
    , onRecvStateHandshake
    , extensionLookup
    ) where

import Control.Concurrent.MVar

import Network.TLS.Parameters
import Network.TLS.Compression
import Network.TLS.Context.Internal
import Network.TLS.Session
import Network.TLS.Struct
import Network.TLS.IO
import Network.TLS.State hiding (getNegotiatedProtocol)
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.State
import Network.TLS.Record.State
import Network.TLS.Measurement
import Network.TLS.Types
import Network.TLS.Cipher
import Network.TLS.Util
import Network.TLS.ErrT
import Data.List (find)
import Data.ByteString.Char8 (ByteString)

import Control.Monad.State.Strict


errorToAlert :: TLSError -> Packet
errorToAlert (Error_Protocol (_, _, ad)) = Alert [(AlertLevel_Fatal, ad)]
errorToAlert _                           = Alert [(AlertLevel_Fatal, InternalError)]

unexpected :: String -> Maybe [Char] -> ErrT TLSError IO a
unexpected msg expected = left $ Error_Packet_unexpected msg (maybe "" (" expected: " ++) expected)

newSession :: Context -> IO Session
newSession ctx
    | supportedSession $ ctxSupported ctx = Session . either (const Nothing) Just <$> runErrT (getStateRNG ctx 32)
    | otherwise                           = return $ Session Nothing

-- | when a new handshake is done, wrap up & clean up.
handshakeTerminate :: Context -> ErrT TLSError IO ()
handshakeTerminate ctx = do
    session <- usingStateT ctx getSession
    -- only callback the session established if we have a session
    case session of
        Session (Just sessionId) -> do
            msessionData <- getSessionData ctx
            sessionData <- hoistMaybe (Error_Misc "session-data") msessionData
            liftIO $ sessionEstablish (sharedSessionManager $ ctxShared ctx) sessionId sessionData
        _ -> return ()
    -- forget most handshake data and reset bytes counters.
    liftIO $ modifyMVar_ (ctxHandshake ctx) $ \ mhshake ->
        case mhshake of
            Nothing -> return Nothing
            Just hshake ->
                return $ Just (newEmptyHandshake (hstClientVersion hshake) (hstClientRandom hshake))
                    { hstServerRandom = hstServerRandom hshake
                    , hstMasterSecret = hstMasterSecret hshake
                    }
    liftIO $ do
        updateMeasure ctx resetBytesCounters
        -- mark the secure connection up and running.
        setEstablished ctx True
    return ()

sendChangeCipherAndFinish :: Context
                          -> Role
                          -> ErrT TLSError IO ()
sendChangeCipherAndFinish ctx role = do
    sendPacket ctx ChangeCipherSpec
    liftIO $ contextFlush ctx
    cf <- usingStateT ctx getVersion >>= \ver -> usingHStateT ctx $ getHandshakeDigest ver role
    sendPacket ctx (Handshake [Finished cf])
    liftIO $ contextFlush ctx

recvChangeCipherAndFinish :: Context -> ErrT TLSError IO ()
recvChangeCipherAndFinish ctx = runRecvState ctx (RecvStateNext expectChangeCipher)
  where expectChangeCipher ChangeCipherSpec = return $ RecvStateHandshake expectFinish
        expectChangeCipher p                = unexpected (show p) (Just "change cipher")
        expectFinish (Finished _) = return RecvStateDone
        expectFinish p            = unexpected (show p) (Just "Handshake Finished")

data RecvState m =
      RecvStateNext (Packet -> m (RecvState m))
    | RecvStateHandshake (Handshake -> m (RecvState m))
    | RecvStateDone

recvPacketHandshake :: Context -> ErrT TLSError IO [Handshake]
recvPacketHandshake ctx = do
    pkts <- newErrT $ recvPacket ctx
    case pkts of
        Handshake l -> return l
        x           -> fail ("unexpected type received. expecting handshake and got: " ++ show x)


-- | process a list of handshakes message in the recv state machine.
onRecvStateHandshake :: Context -> RecvState (ErrT TLSError IO) -> [Handshake] -> ErrT TLSError IO (RecvState ((ErrT TLSError IO)))
onRecvStateHandshake _   recvState [] = return recvState
onRecvStateHandshake ctx (RecvStateHandshake f) (x:xs) = do
    nstate <- f x
    processHandshake ctx x
    onRecvStateHandshake ctx nstate xs
onRecvStateHandshake _ _ _   = unexpected "spurious handshake" Nothing

runRecvState :: Context -> RecvState (ErrT TLSError IO) -> ErrT TLSError IO ()
runRecvState _   (RecvStateDone)   = return ()
runRecvState ctx (RecvStateNext f) = newErrT (recvPacket ctx) >>= f >>= runRecvState ctx
runRecvState ctx iniState          = recvPacketHandshake ctx >>= onRecvStateHandshake ctx iniState >>= runRecvState ctx

getSessionData :: Context -> ErrT TLSError IO (Maybe SessionData)
getSessionData ctx = do
    ver <- usingStateT ctx getVersion
    sni <- usingStateT ctx getClientSNI
    mms <- usingHStateT ctx (gets hstMasterSecret)
    tx  <- liftIO $ readMVar (ctxTxState ctx)
    sc <- hoistMaybe (Error_Misc "cipher: Nothing") $ stCipher tx
    case mms of
        Nothing -> return Nothing
        Just ms -> return $ Just $ SessionData
                        { sessionVersion     = ver
                        , sessionCipher      = cipherID sc
                        , sessionCompression = compressionID $ stCompression tx
                        , sessionClientSNI   = sni
                        , sessionSecret      = ms
                        }

extensionLookup :: ExtensionID -> [ExtensionRaw] -> Maybe ByteString
extensionLookup toFind = fmap (\(ExtensionRaw _ content) -> content)
                       . find (\(ExtensionRaw eid _) -> eid == toFind)
