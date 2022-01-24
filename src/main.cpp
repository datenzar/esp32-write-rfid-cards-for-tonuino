/**
 * ----------------------------------------------------------------------------
 * This program allows to program cards for the Tonuino. It will read a 
 * 18 character string of hex code and write it to the next RFID card presented * 
 * 
 */

#include <Arduino.h>

#include <SPI.h>
#include <MFRC522.h>

#define RST_PIN 21 // Configurable, see typical pin layout above
#define SS_PIN 	5   // Configurable, see typical pin layout above
#define IRQ_PIN 4           // Configurable, depends on hardware
#define MISO 	19
#define MOSI 	23
#define SCK 	18
#define BAUD_RATE	115200

MFRC522 mfrc522(SS_PIN, RST_PIN); // Create MFRC522 instance.

MFRC522::MIFARE_Key key;

// pre define methods
void dump_byte_array(const byte *byteArray, byte arraySize);
void formatValueBlock(byte blockAddr);
void self_test();
void write_card();

byte nibble(char c);
void hexCharacterStringToBytes(byte *byteArray, const char *hexString);

byte buf[] = {
		0x13, 0x37, 0xB3, 0x47,
		0x01, 0x01, 0x02, 0x00,
		0, 0, 0, 0,
		0, 0, 0, 0};

void setup()
{
    Serial.begin(BAUD_RATE); // Initialize serial communications with the PC
	while (!Serial); // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
	SPI.begin(SCK, MISO, MOSI, SS_PIN); // Init SPI bus
	mfrc522.PCD_Init(SS_PIN, RST_PIN);	// Init MFRC522 card
	delay(4);							// Optional delay. Some board do need more time after init to be ready, see Readme
	self_test();

	// Prepare the key (used both as key A and as key B)
	// using FFFFFFFFFFFFh which is the default at chip delivery from the factory
	for (byte i = 0; i < 6; i++)
	{
		key.keyByte[i] = 0xFF;
	}

	Serial.println(F("Scan a MIFARE Classic PICC to demonstrate Value Block mode."));
	Serial.print(F("Using key (for A and B):"));
	dump_byte_array(key.keyByte, MFRC522::MF_KEY_SIZE);

	Serial.println(F("BEWARE: Data will be written to the PICC, in sector #1"));
	Serial.print("Enter text: ");
}

/**
 * Main loop.
 */
void loop()
{
	String text = Serial.readStringUntil('\r');	
	unsigned int bufferSize = 9;
	// byte textBuffer[] = "123456789012345678";	

	if(text.length() == bufferSize * 2) {
		// unsigned char[] buf = unsigned char[18];
		Serial.print("\nEntered text: ");
		Serial.println(text);

		// text.getBytes(buf, bufferSize);
		hexCharacterStringToBytes(buf, text.c_str());
		dump_byte_array(buf, bufferSize);
	}

	// Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
	if (!mfrc522.PICC_IsNewCardPresent())
		return;

	// Select one of the cards
	if (!mfrc522.PICC_ReadCardSerial())
		return;

	// Show some details of the PICC (that is: the tag/card)
	Serial.print(F("Card UID:"));
	dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);

	Serial.print(F("PICC type: "));
	MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
	Serial.println(mfrc522.PICC_GetTypeName(piccType));

	// Check for compatibility
	if (piccType != MFRC522::PICC_TYPE_MIFARE_MINI && piccType != MFRC522::PICC_TYPE_MIFARE_1K && piccType != MFRC522::PICC_TYPE_MIFARE_4K)
	{
		Serial.println(F("This sample only works with MIFARE Classic cards."));
		return;
	}

	// In this sample we use the second sector,
	// that is: sector #1, covering block #4 up to and including block #7
	byte sector = 1;
	byte valueBlock = sector * 4 + 0;
	byte trailerBlock = sector * 4 + 3;
	MFRC522::StatusCode status;

	// Authenticate using key A
	Serial.println(F("Authenticating using key A..."));
	status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
	if (status != MFRC522::STATUS_OK)
	{
		Serial.print(F("PCD_Authenticate() failed: "));
		Serial.println(mfrc522.GetStatusCodeName(status));
		return;
	}

	// Show the whole sector as it currently is
	Serial.println(F("Current data in sector:"));
	mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), &key, sector);
	Serial.println();

	Serial.print("Writing to card: ");
	dump_byte_array(buf, bufferSize);

	// Serial.println((char*)values);
	status = mfrc522.MIFARE_Write(valueBlock, buf, 16);
	if (status != MFRC522::STATUS_OK)
	{
		Serial.print(F("MIFARE_Write() failed: "));
		Serial.println(mfrc522.GetStatusCodeName(status));
	}

	// Dump the sector data
	mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), &key, sector);
	Serial.println();

	// Halt PICC
	mfrc522.PICC_HaltA();
	// Stop encryption on PCD
	mfrc522.PCD_StopCrypto1();
}

/**
 * Perform a quick self test to ensure the reader is working properly
 */
void self_test()
{
	Serial.println(F("*****************************"));
	Serial.println(F("MFRC522 Digital self test"));
	Serial.println(F("*****************************"));
	mfrc522.PCD_DumpVersionToSerial(); // Show version of PCD - MFRC522 Card Reader
	Serial.println(F("-----------------------------"));
	Serial.println(F("Only known versions supported"));
	Serial.println(F("-----------------------------"));
	Serial.println(F("Performing test..."));
	bool result = mfrc522.PCD_PerformSelfTest(); // perform the test
	Serial.println(F("-----------------------------"));
	Serial.print(F("Result: "));
	if (result)
		Serial.println(F("OK"));
	else
		Serial.println(F("DEFECT or UNKNOWN"));
	Serial.println();
}

/**
 * Helper routine to dump a byte array as hex values to Serial.
 */
void dump_byte_array(const byte *byteArray, byte arraySize)
{
	for (byte i = 0; i < arraySize; i++)
	{
		Serial.print(byteArray[i] < 0x10 ? " 0" : " ");
		Serial.print(byteArray[i], HEX);
		Serial.println();
	}
}

void hexCharacterStringToBytes(byte *byteArray, const char *hexString)
{
  bool oddLength = strlen(hexString) & 1;

  byte currentByte = 0;
  byte byteIndex = 0;

  for (byte charIndex = 0; charIndex < strlen(hexString); charIndex++)
  {
    bool oddCharIndex = charIndex & 1;

    if (oddLength)
    {
      // If the length is odd
      if (oddCharIndex)
      {
        // odd characters go in high nibble
        currentByte = nibble(hexString[charIndex]) << 4;
      }
      else
      {
        // Even characters go into low nibble
        currentByte |= nibble(hexString[charIndex]);
        byteArray[byteIndex++] = currentByte;
        currentByte = 0;
      }
    }
    else
    {
      // If the length is even
      if (!oddCharIndex)
      {
        // Odd characters go into the high nibble
        currentByte = nibble(hexString[charIndex]) << 4;
      }
      else
      {
        // Odd characters go into low nibble
        currentByte |= nibble(hexString[charIndex]);
        byteArray[byteIndex++] = currentByte;
        currentByte = 0;
      }
    }
  }
}

// converts hex representing char (0-F) to halfbyte (4-bit) value
byte nibble(char c)
{
	// Return byte for numbers
	if (c >= '0' && c <= '9')
		return c - '0';

	// Return byte for lowercase values
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;

	// Return byte for uppercase values
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	return 0;  // Not a valid hexadecimal character
}
