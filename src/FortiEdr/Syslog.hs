{-# language BangPatterns #-}
{-# language MagicHash #-}
{-# language MultiWayIf #-}

module FortiEdr.Syslog
  ( Attribute(..)
  , decode
  ) where

import Net.Types (IP)
import Data.Foldable (foldl')
import Data.Bytes (Bytes)
import Data.Word (Word64)
import Data.Primitive (SmallArray)
import GHC.Exts (Ptr(Ptr))

import qualified Data.Bytes as Bytes
import qualified Data.Bytes.Parser as Parser
import qualified Data.Bytes.Parser.Latin as Latin
import qualified GHC.Exts as Exts
import qualified Net.IP as IP

-- | Decode the message in a FortiEDR syslog. Do not pass this function the
-- full syslog:
--
-- > <133>1 2021-05-25T15:47:37.000Z layer3com.console.ensilo.com FortiEDR - - - Message Type: Security Event;Organization: WidgetCorp;...
--
-- Rather, use @Syslog.Ietf.decode@ to get the message from FortiEDR\'s
-- RFC 5424 syslog:
--
-- > Message Type: Security Event;Organization: WidgetCorp;...
--
-- Then, apply this function to that message.
decode :: Bytes -> SmallArray Attribute
decode !msg = Exts.fromList $ foldl'
  (\acc chunk -> case Bytes.split1 0x3A chunk of
    Just (key,v) | Just (0x20,value) <- Bytes.uncons v ->
      if | Bytes.equalsCString (Ptr "Action"#) key -> Action value : acc
         | Bytes.equalsCString (Ptr "Classification"#) key -> Classification value : acc
         | Bytes.equalsCString (Ptr "Count"#) key -> case decodeW64 value of
             Just value' -> Count value' : acc
             Nothing -> acc
         | Bytes.equalsCString (Ptr "Destination"#) key -> Destination value : acc
         | Bytes.equalsCString (Ptr "Device Name"#) key -> DeviceName value : acc
         | Bytes.equalsCString (Ptr "DeviceState"#) key -> DeviceState value : acc
         | Bytes.equalsCString (Ptr "Event ID"#) key -> case decodeW64 value of
             Just value' -> EventId value' : acc
             Nothing -> acc
         | Bytes.equalsCString (Ptr "Message Type"#) key -> MessageType value : acc
         | Bytes.equalsCString (Ptr "Operating System"#) key -> OperatingSystem value : acc
         | Bytes.equalsCString (Ptr "Organization"#) key -> Organization value : acc
         | Bytes.equalsCString (Ptr "Organization ID"#) key -> case decodeW64 value of
             Just value' -> OrganizationId value' : acc
             Nothing -> acc
         | Bytes.equalsCString (Ptr "Process Name"#) key -> ProcessName value : acc
         | Bytes.equalsCString (Ptr "Process Path"#) key -> ProcessPath value : acc
         | Bytes.equalsCString (Ptr "Process Type"#) key -> ProcessType value : acc
         | Bytes.equalsCString (Ptr "Raw Data ID"#) key -> case decodeW64 value of
             Just value' -> RawDataId value' : acc
             Nothing -> acc
         | Bytes.equalsCString (Ptr "Rules List"#) key -> RulesList value : acc
         | Bytes.equalsCString (Ptr "Severity"#) key -> Severity value : acc
         | Bytes.equalsCString (Ptr "Source IP"#) key -> case decodeIp value of
             Just value' -> SourceIp value' : acc
             Nothing -> acc
         | Bytes.equalsCString (Ptr "Users"#) key -> Users value : acc
         | otherwise -> acc
    _ -> acc
  ) [] (Bytes.split 0x3B msg)

-- ^ Data constructor annatotions describe the field name as it appears in
-- the logs.
data Attribute
  = Action !Bytes -- ^ Action
  | Classification !Bytes -- ^ Classification
  | Count !Word64 -- ^ Count
  | Destination !Bytes -- ^ Destination
  | DeviceName !Bytes -- ^ Device Name
  | DeviceState !Bytes -- ^ Device State
  | EventId !Word64 -- ^ Event ID
  | MessageType !Bytes -- ^ Message Type
  | OperatingSystem !Bytes -- ^ Operating System
  | Organization !Bytes -- ^ Organization
  | OrganizationId !Word64 -- ^ Organization ID
  | ProcessName !Bytes -- ^ Process Name
  | ProcessPath !Bytes -- ^ Process Path
  | ProcessType !Bytes -- ^ Process Type
  | RawDataId !Word64 -- ^ Raw Data ID
  | RulesList !Bytes -- ^ Rules List
  | Severity !Bytes -- ^ Severity
  | SourceIp {-# UNPACK #-} !IP -- ^ Source IP
  | Users !Bytes -- ^ Users

decodeIp :: Bytes -> Maybe IP
decodeIp = Parser.parseBytesMaybe (IP.parserUtf8Bytes () <* Parser.endOfInput ())

decodeW64 :: Bytes -> Maybe Word64
decodeW64 = Parser.parseBytesMaybe (Latin.decWord64 () <* Parser.endOfInput ())
