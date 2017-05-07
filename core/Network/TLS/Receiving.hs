-- |
-- Module      : Network.TLS.Receiving
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Receiving module contains calls related to unmarshalling packets according
-- to the TLS state
--
{-# LANGUAGE FlexibleContexts #-}

module Network.TLS.Receiving
    ( processPacket
    ) where

import Control.Monad.State.Strict
import Control.Concurrent.MVar

import Network.TLS.Context.Internal
import Network.TLS.Struct
import Network.TLS.ErrT
import Network.TLS.Record
import Network.TLS.Packet
import Network.TLS.Wire
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Cipher
import Network.TLS.Util

processPacket :: Context -> Record Plaintext -> IO (Either TLSError Packet)

processPacket _ (Record ProtocolType_AppData _ fragment) = return $ Right $ AppData $ fragmentGetBytes fragment

processPacket _ (Record ProtocolType_Alert _ fragment) = return (Alert `fmapEither` (decodeAlerts $ fragmentGetBytes fragment))

processPacket ctx (Record ProtocolType_ChangeCipherSpec _ fragment) =
    case decodeChangeCipherSpec $ fragmentGetBytes fragment of
        Left err -> return $ Left err
        Right _  -> runErrT $ do
                        switchRxEncryption ctx
                        return ChangeCipherSpec

processPacket ctx (Record ProtocolType_Handshake ver fragment) = do
    keyxchg <- getHState ctx >>= \hs -> return $ (hs >>= hstPendingCipher >>= Just . cipherKeyExchange)
    usingState ctx $ do
        let currentParams = CurrentParams
                            { cParamsVersion     = ver
                            , cParamsKeyXchgType = keyxchg
                            }
        -- get back the optional continuation, and parse as many handshake record as possible.
        mCont <- gets stHandshakeRecordCont
        modify (\st -> st { stHandshakeRecordCont = Nothing })
        hss   <- parseMany currentParams mCont (fragmentGetBytes fragment)
        return $ Handshake hss
  where parseMany currentParams mCont bs =
            case maybe decodeHandshakeRecord id mCont $ bs of
                GotError err                -> throwError err
                GotPartial cont             -> modify (\st -> st { stHandshakeRecordCont = Just cont }) >> return []
                GotSuccess (ty,content)     ->
                    either throwError (return . (:[])) $ decodeHandshake currentParams ty content
                GotSuccessRemaining (ty,content) lft ->
                    case decodeHandshake currentParams ty content of
                        Left err -> throwError err
                        Right hh -> (hh:) `fmap` parseMany currentParams Nothing lft

processPacket _ (Record ProtocolType_DeprecatedHandshake _ fragment) =
    case decodeDeprecatedHandshake $ fragmentGetBytes fragment of
        Left err -> return $ Left err
        Right hs -> return $ Right $ Handshake [hs]

switchRxEncryption :: Context -> ErrT TLSError IO ()
switchRxEncryption ctx =
    usingHStateT ctx (gets hstPendingRxState) >>= \ mrx ->
        mcase mrx (left $ Error_Misc "rx-state: Nothing") $ \ rx ->
            liftIO $ modifyMVar_ (ctxRxState ctx) (const $ pure rx)
