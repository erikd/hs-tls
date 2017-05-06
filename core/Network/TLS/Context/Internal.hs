-- |
-- Module      : Network.TLS.Context.Internal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Context.Internal
    (
    -- * Context configuration
      ClientParams(..)
    , ServerParams(..)
    , defaultParamsClient
    , SessionID
    , SessionData(..)
    , MaxFragmentEnum(..)
    , Measurement(..)

    -- * Context object and accessor
    , Context(..)
    , Hooks(..)
    , ctxEOF
    , ctxHasSSLv2ClientHello
    , ctxDisableSSLv2ClientHello
    , ctxEstablished
    , withLog
    , ctxWithHooks
    , contextModifyHooks
    , setEOF
    , setEstablished
    , contextFlush
    , contextClose
    , contextSend
    , contextRecv
    , updateMeasure
    , withMeasure
    , withReadLock
    , withReadLockT
    , withWriteLock
    , withWriteLockT
    , withStateLock
    , withRWLock
    , withRWLockT

    -- * information
    , Information(..)
    , contextGetInformation

    -- * Using context states
    , throwCore
    , usingState
    , usingState_
    , usingStateT
    , runTxState
    , runTxStateT
    , runRxState
    , usingHState
    , usingHState_
    , usingHStateT
    , getHState
    , getStateRNG
    ) where

import Network.TLS.Backend
import Network.TLS.Extension
import Network.TLS.Cipher
import Network.TLS.Credentials (Credentials)
import Network.TLS.Struct
import Network.TLS.Compression (Compression)
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Hooks
import Network.TLS.Record.State
import Network.TLS.Parameters
import Network.TLS.Measurement
import Network.TLS.ErrT
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Control.Concurrent.MVar
import Control.Monad.State.Strict
import Control.Exception (Exception(), mask, onException, throwIO, )
import Data.IORef
import Data.Tuple


-- | Information related to a running context, e.g. current cipher
data Information = Information
    { infoVersion      :: Version
    , infoCipher       :: Cipher
    , infoCompression  :: Compression
    , infoMasterSecret :: Maybe ByteString
    , infoClientRandom :: Maybe ClientRandom
    , infoServerRandom :: Maybe ServerRandom
    } deriving (Show,Eq)

-- | A TLS Context keep tls specific state, parameters and backend information.
data Context = Context
    { ctxConnection       :: Backend   -- ^ return the backend object associated with this context
    , ctxSupported        :: Supported
    , ctxShared           :: Shared
    , ctxCiphers          :: Credentials -> [Cipher]  -- ^ list of allowed ciphers according to parameters
                                                      -- and additional credentials
    , ctxState            :: MVar TLSState
    , ctxMeasurement      :: IORef Measurement
    , ctxEOF_             :: IORef Bool    -- ^ has the handle EOFed or not.
    , ctxEstablished_     :: IORef Bool    -- ^ has the handshake been done and been successful.
    , ctxNeedEmptyPacket  :: IORef Bool    -- ^ empty packet workaround for CBC guessability.
    , ctxSSLv2ClientHello :: IORef Bool    -- ^ enable the reception of compatibility SSLv2 client hello.
                                           -- the flag will be set to false regardless of its initial value
                                           -- after the first packet received.
    , ctxTxState          :: MVar RecordState -- ^ current tx state
    , ctxRxState          :: MVar RecordState -- ^ current rx state
    , ctxHandshake        :: MVar (Maybe HandshakeState) -- ^ optional handshake state
    , ctxDoHandshake      :: Context -> ErrT TLSError IO ()
    , ctxDoHandshakeWith  :: Context -> Handshake -> ErrT TLSError IO ()
    , ctxHooks            :: IORef Hooks   -- ^ hooks for this context
    , ctxLockWrite        :: MVar ()       -- ^ lock to use for writing data (including updating the state)
    , ctxLockRead         :: MVar ()       -- ^ lock to use for reading data (including updating the state)
    , ctxLockState        :: MVar ()       -- ^ lock used during read/write when receiving and sending packet.
                                           -- it is usually nested in a write or read lock.
    }

updateMeasure :: Context -> (Measurement -> Measurement) -> IO ()
updateMeasure ctx f = do
    x <- readIORef (ctxMeasurement ctx)
    writeIORef (ctxMeasurement ctx) $! f x

withMeasure :: Context -> (Measurement -> IO a) -> IO a
withMeasure ctx f = readIORef (ctxMeasurement ctx) >>= f

contextFlush :: Context -> IO ()
contextFlush = backendFlush . ctxConnection

contextClose :: Context -> IO ()
contextClose = backendClose . ctxConnection

-- | Information about the current context
contextGetInformation :: Context -> IO (Maybe Information)
contextGetInformation ctx = do
    ver    <- usingState_ ctx $ gets stVersion
    hstate <- getHState ctx
    let (ms, cr, sr) = case hstate of
                           Just st -> (hstMasterSecret st,
                                       Just (hstClientRandom st),
                                       hstServerRandom st)
                           Nothing -> (Nothing, Nothing, Nothing)
    res <- runRxState ctx $ gets $ \st -> (stCipher st, stCompression st)
    case res of
        Left _ -> return Nothing
        Right (cipher,comp) ->
            case (ver, cipher) of
                (Just v, Just c) -> return $ Just $ Information v c comp ms cr sr
                _                -> return Nothing

contextSend :: Context -> ByteString -> IO ()
contextSend c b = updateMeasure c (addBytesSent $ B.length b) >> (backendSend $ ctxConnection c) b

contextRecv :: Context -> Int -> IO ByteString
contextRecv c sz = updateMeasure c (addBytesReceived sz) >> (backendRecv $ ctxConnection c) sz

ctxEOF :: Context -> IO Bool
ctxEOF ctx = readIORef $ ctxEOF_ ctx

ctxHasSSLv2ClientHello :: Context -> IO Bool
ctxHasSSLv2ClientHello ctx = readIORef $ ctxSSLv2ClientHello ctx

ctxDisableSSLv2ClientHello :: Context -> IO ()
ctxDisableSSLv2ClientHello ctx = writeIORef (ctxSSLv2ClientHello ctx) False

setEOF :: Context -> IO ()
setEOF ctx = writeIORef (ctxEOF_ ctx) True

ctxEstablished :: Context -> IO Bool
ctxEstablished ctx = readIORef $ ctxEstablished_ ctx

ctxWithHooks :: Context -> (Hooks -> IO a) -> IO a
ctxWithHooks ctx f = readIORef (ctxHooks ctx) >>= f

contextModifyHooks :: Context -> (Hooks -> Hooks) -> IO ()
contextModifyHooks ctx f = modifyIORef (ctxHooks ctx) f

setEstablished :: Context -> Bool -> IO ()
setEstablished ctx v = writeIORef (ctxEstablished_ ctx) v

withLog :: Context -> (Logging -> IO ()) -> IO ()
withLog ctx f = ctxWithHooks ctx (f . hookLogging)

usingState :: Context -> TLSSt a -> IO (Either TLSError a)
usingState ctx f =
    modifyMVar (ctxState ctx) $ \st ->
            let (a, newst) = runTLSState f st
             in newst `seq` return (newst, a)

usingStateT :: Context -> TLSSt a -> ErrT TLSError IO a
usingStateT ctx = newErrT . usingState ctx

usingState_ :: Context -> TLSSt a -> IO a
usingState_ ctx f =
    either throwCore return =<< usingState ctx f

usingHState :: Context -> HandshakeM a -> IO (Either TLSError a)
usingHState ctx f = liftIO $ modifyMVar (ctxHandshake ctx) $ \mst ->
    case mst of
        Nothing -> return (Nothing, Left $ Error_Misc "missing handshake")
        Just st -> return $ swap (Just `fmap` runHandshake st f)

usingHState_ :: Context -> HandshakeM a -> IO a
usingHState_ ctx f =
    either throwCore return =<< usingHState ctx f

usingHStateT :: Context -> HandshakeM a -> ErrT TLSError IO a
usingHStateT ctx = newErrT . usingHState ctx

getHState :: Context -> IO (Maybe HandshakeState)
getHState ctx = liftIO $ readMVar (ctxHandshake ctx)

runTxState :: Context -> RecordM a -> IO (Either TLSError a)
runTxState ctx f = do
    ver <- usingState_ ctx (getVersionWithDefault $ maximum $ supportedVersions $ ctxSupported ctx)
    modifyMVar (ctxTxState ctx) $ \st ->
        case runRecordM f ver st of
            Left err         -> return (st, Left err)
            Right (a, newSt) -> return (newSt, Right a)

runTxStateT :: Context -> RecordM a -> ErrT TLSError IO a
runTxStateT ctx = newErrT . runTxState ctx

runRxState :: Context -> RecordM a -> IO (Either TLSError a)
runRxState ctx f = do
    ver <- usingState_ ctx getVersion
    modifyMVar (ctxRxState ctx) $ \st ->
        case runRecordM f ver st of
            Left err         -> return (st, Left err)
            Right (a, newSt) -> return (newSt, Right a)

getStateRNG :: Context -> Int -> IO ByteString
getStateRNG ctx n = usingState_ ctx $ genRandom n

withReadLock :: Context -> IO a -> IO a
withReadLock ctx f = withMVar (ctxLockRead ctx) (const f)

withReadLockT :: Context -> ErrT TLSError IO a -> ErrT TLSError IO a
withReadLockT ctx f = withMVarT (ctxLockRead ctx) (const f)

withWriteLock :: Context -> IO a -> IO a
withWriteLock ctx f = withMVar (ctxLockWrite ctx) (const f)

withWriteLockT :: Context -> ErrT TLSError IO a -> ErrT TLSError IO a
withWriteLockT ctx f = withMVarT (ctxLockWrite ctx) (const f)

withRWLock :: Context -> IO a -> IO a
withRWLock ctx f = withReadLock ctx $ withWriteLock ctx f

withRWLockT :: Context -> ErrT TLSError IO a -> ErrT TLSError IO a
withRWLockT ctx f = withReadLockT ctx $ withWriteLockT ctx f

withStateLock :: Context -> IO a -> IO a
withStateLock ctx f = withMVar (ctxLockState ctx) (const f)

-- | withMar lifted into `ErrT e IO`.
withMVarT :: MVar a -> (a -> ErrT e IO b) -> ErrT e IO b
withMVarT m f = newErrT $ withMVar m (runErrT . f)
