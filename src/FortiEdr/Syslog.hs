{-# language BangPatterns #-}
{-# language MagicHash #-}
{-# language MultiWayIf #-}
{-# language NumericUnderscores #-}
{-# language TypeApplications #-}

module FortiEdr.Syslog
  ( Attribute(..)
  , decode
  ) where

import Chronos (Datetime)
import Control.Monad (when)
import Net.Types (IP,Mac)
import Data.Foldable (foldl')
import Data.Bytes (Bytes)
import Data.Int (Int64)
import Data.Word (Word8,Word32,Word64)
import Data.Primitive (PrimArray,SmallArray)
import GHC.Exts (Ptr(Ptr))

import qualified Chronos
import qualified Data.Primitive.Contiguous as C
import qualified Data.Bytes as Bytes
import qualified Data.Bytes.Parser as Parser
import qualified Data.Bytes.Parser.Latin as Latin
import qualified GHC.Exts as Exts
import qualified Net.IP as IP
import qualified Net.Mac as Mac

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
         | Bytes.equalsCString (Ptr "First Seen"#) key -> case decodeTime value of
             Just value' -> FirstSeen value' : acc
             Nothing -> acc
         | Bytes.equalsCString (Ptr "Last Seen"#) key -> case decodeTime value of
             Just value' -> LastSeen value' : acc
             Nothing -> acc
         | Bytes.equalsCString (Ptr "MAC Address"#) key ->
             let !value' = decodeMacAddresses value
              in MacAddress value' : acc
         | Bytes.equalsCString (Ptr "Message Type"#) key -> MessageType value : acc
         | Bytes.equalsCString (Ptr "Operating System"#) key -> OperatingSystem value : acc
         | Bytes.equalsCString (Ptr "Organization"#) key -> Organization value : acc
         | Bytes.equalsCString (Ptr "Organization ID"#) key -> case decodeW64 value of
             Just value' -> OrganizationId value' : acc
             Nothing -> acc
         | Bytes.equalsCString (Ptr "Process Hash"#) key -> ProcessHash value : acc
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
  | FirstSeen !Datetime -- ^ First Seen
  | LastSeen !Datetime -- ^ Last Seen
  | MessageType !Bytes -- ^ Message Type
  | MacAddress !(PrimArray Mac) -- ^ MAC Address
  | OperatingSystem !Bytes -- ^ Operating System
  | Organization !Bytes -- ^ Organization
  | OrganizationId !Word64 -- ^ Organization ID
  | ProcessHash !Bytes -- ^ Process Hash
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

decodeTime :: Bytes -> Maybe Datetime
decodeTime = Parser.parseBytesMaybe parserTime

decodeMacAddresses :: Bytes -> PrimArray Mac
decodeMacAddresses addrs = C.mapMaybe
  ( \b -> Mac.decodeUtf8Bytes (Bytes.fromByteArray b)
  ) (Bytes.splitU 0x2C addrs)

parserTime :: Parser.Parser () s Datetime
parserTime = do
  !day <- Latin.decWord8 ()
  when (day > 31) (Parser.fail ())
  Latin.char () '-'
  !monthName <- Parser.takeTrailedBy () 0x2D
  !month <- case Bytes.length monthName of
    3 -> pure $! resolveMonth monthName
    _ -> Parser.fail ()
  !year <- Latin.decWord32 ()
  when (year > 2100) (Parser.fail ())
  Latin.char2 () ',' ' '
  !hour <- Latin.decWord8 ()
  when (hour > 23) (Parser.fail ())
  Latin.char () ':'
  !minute <- Latin.decWord8 ()
  when (minute > 59) (Parser.fail ())
  Latin.char () ':'
  !second <- Latin.decWord8 ()
  when (second > 59) (Parser.fail ())
  Parser.endOfInput ()
  pure Chronos.Datetime
    { Chronos.datetimeDate = Chronos.Date
      { Chronos.dateYear = Chronos.Year (fromIntegral @Word32 @Int year)
      , Chronos.dateMonth = month
      , Chronos.dateDay = Chronos.DayOfMonth (fromIntegral @Word8 @Int day)
      }
    , Chronos.datetimeTime = Chronos.TimeOfDay
      { Chronos.timeOfDayHour = fromIntegral @Word8 @Int hour
      , Chronos.timeOfDayMinute = fromIntegral @Word8 @Int minute
      , Chronos.timeOfDayNanoseconds = fromIntegral @Word8 @Int64 second * 1_000_000_000
      }
    }
  
-- Precondition: length of bytes is 3
resolveMonth :: Bytes -> Chronos.Month
resolveMonth b
  | Bytes.equalsLatin3 'A' 'p' 'r' b = Chronos.april
  | Bytes.equalsLatin3 'A' 'u' 'g' b = Chronos.august
  | Bytes.equalsLatin3 'D' 'e' 'c' b = Chronos.december
  | Bytes.equalsLatin3 'F' 'e' 'b' b = Chronos.february
  | Bytes.equalsLatin3 'J' 'a' 'n' b = Chronos.january
  | Bytes.equalsLatin3 'J' 'u' 'l' b = Chronos.july
  | Bytes.equalsLatin3 'J' 'u' 'n' b = Chronos.june
  | Bytes.equalsLatin3 'M' 'a' 'r' b = Chronos.march
  | Bytes.equalsLatin3 'M' 'a' 'y' b = Chronos.may
  | Bytes.equalsLatin3 'N' 'o' 'v' b = Chronos.november
  | Bytes.equalsLatin3 'O' 'c' 't' b = Chronos.october
  | Bytes.equalsLatin3 'S' 'e' 'p' b = Chronos.september
  | otherwise = Chronos.Month 12
