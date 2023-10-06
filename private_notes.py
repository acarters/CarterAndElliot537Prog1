import pickle
import os # Example on crypto documentation imports this, so I do too. 
from cryptography.hazmat.primitives import hashes, hmac # Import the SHA256 hash, and the HMAC derived from it.
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # Import the ciphers, algorithms and modes needed to perform AES.
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # Import AES-GCM.
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # Import the password generation function from the cryptography library.
from cryptography.hazmat.primitives import padding

class PrivNotes:
  MAX_NOTE_LEN = 2048; # The maximum length a note can be that is valid in the key value store.
  passwordSalt = os.urandom(16); # Generate a 16 byte (128 bit) salt for generating the key. The only true random value we are allowed.
  
  """
  Constructor.
  Args:
    password (str) : password for accessing the notes
    data (str) [Optional] : a hex-encoded serialized representation to load
                            (defaults to None, which initializes an empty notes database)
    checksum (str) [Optional] : a hex-encoded checksum used to protect the data against
                                possible rollback attacks (defaults to None, in which
                                case, no rollback protection is guaranteed)
  Raises:
    ValueError : malformed serialized format
  """
  def __init__(self, password, data = None, checksum = None):
    self.kvs = {} # Initialize the key-value store to be empty.
    kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = self.passwordSalt, iterations = 2000000) # Define the kdf algorithm by running SHA256 2 million times using the salt we generated.
    self.key = kdf.derive(bytes(password, 'ascii')) # Generate the key using the defined kdf algorithm.
    self.HMACKey = self.runHMAC(self.key, bytes("I love the number 37", 'ascii')) # Generate new key from source key using HMAC. This key is for HMAC operations. 
    self.AESKey = self.runHMAC(self.key, bytes("I HATE the number 37", 'ascii')) # Generate new key from source key using HMAC. This key is for AES operations.
    self.AESGCMKey = self.runHMAC(self.key, bytes("I am ambivalent towards the number 37", 'ascii')) # Generate new key from source key using HMAC. This key is for AES-GCM operations.
    passwordHMAC = self.runHMAC(self.HMACKey, bytes(password, 'ascii')) # run HMAC on the password. This output is collision-resistant, pseudo-random, and irreversible, making it perfect for verifying passwords without exposing the password.
    pwdTitleHMAC = self.runHMAC(self.HMACKey, bytes("passwordHMAC", 'ascii')) #run HMAC on the title of the password. This is to match the formatting of the rest of the tags. "passwordHMAC" is an arbitrary string.
    if checksum is not None: # Checksum can only be checked if it's supplied. Otherwise, protection against rollback is not guaranteed.
      dataHash = self.runSHA256(bytes(data, 'ascii')) # Derive the checksum by hashing the serialized data.
      if dataHash != checksum: # Handle the case where the hash of the data does not match the dumped checksum, implying that data has been tampered with.
        raise ValueError("malformed serialized format"); # Return a ValueError if the checksum does not match.
    if data is not None: # Case for data having a value, meaning we are loading from disk rather than starting a new init.
      self.kvs = pickle.loads(bytes.fromhex(data)) # Load the data, so we can look up the HMAC of the password in the kvs.
      if pwdTitleHMAC in self.kvs: # Check to see if the password title exists in the kvs. This handles an error when looking up an invalid tag.
        self.getVal = self.kvs[pwdTitleHMAC] # If the password title exists, set getVal to the password HMAC.
      else:
        self.getVal = None # If the password title does not exist, set getVal to None.
      if passwordHMAC != self.getVal: # Check equality for the password HMAC in the kvs and the password HMAC calculated in init. If they don't match, password is invalid.
        raise ValueError("malformed serialized format"); # Return a ValueError if the password HMAC does not match.
    else: #Case for data not having a value, meaning this is a clean init
      self.kvs[pwdTitleHMAC] = passwordHMAC # Add the password HMAC to the kvs, titled with the HMAC of the title of the password.
  
  """
  runHMAC(self, key, value)

  Helper method that runs HMAC for you.

  Args:
    key : key value that we are running HMAC under.
    value : byte string value to run HMAC on.

  returns:
    hmacValue: the output after running HMAC
  """
  def runHMAC(self, key, value):
    hmacFunc = hmac.HMAC(key, hashes.SHA256()) # Instantiate the HMAC function.
    hmacFunc.update(value) # Use the HMAC function on the title value.
    hmacValue = hmacFunc.finalize() # Output the HMAC title.
    return hmacValue # Return the finished HMAC output.

  """
  runAES(self, key, iv, string)

  Helper method that runs AES for you.
  
  Args:
    key : key value that we are running AES under.
    iv : the nonce.
    string : string value to run AES on.

  returns:
    aesValue: the output after running AES
  """
  def runAES(self, key, iv, string):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv)) # Initialize the cipher, defining it as AES running on CTR mode.
    encryptor = cipher.encryptor() # Create the encryptor from the cipher.
    aesValue = encryptor.update(string) + encryptor.finalize() # Run AES on the string.
    return aesValue # Return the finished AES output.

  """
  AESGCMEncrypt(self, key, nonce, text, aad)

  Encrypt under AES-GCM paradigm, returning a ciphertext.
  
  Args:
    key : key value that we are running AES-GCM under.
    nonce : Arbitrary but non-repeated value for the algorithm to use.
    text : The data that we are encrypting.
    aad : Additional data that should be checked for correctness upon decryption. Should help prevent tampering/swap attacks.

  returns:
    ciphertext: the output after running AES-GCM
  """
  def AESGCMEncrypt(self, key, nonce, paddedData, aad):
    aesgcm = AESGCM(key) # Initialize AES-GCM under our given key.
    ciphertext = aesgcm.encrypt(nonce, paddedData, aad) # Encrypt the data using the given nonce and additional data.
    return ciphertext # Return the resulting ciphertext from encrypting under AES-GCM.

  """
  AESGCMDecrypt(self, key, nonce, ciphertext, aad)

  Decrypt a ciphertext under AES-GCM paradigm, returning a plain text.
  
  Args:
    key : key value that we are running AES-GCM under.
    nonce : Arbitrary but non-repeated value for the algorithm to use.
    ciphertext : The data that we are encrypting.
    aad : Additional data that should be checked for correctness upon decryption. Should help prevent tampering/swap attacks.

  Returns:
    decodedText: the output after running AES-GCM, converted to an ascii string.
  """
  def AESGCMDecrypt(self, key, nonce, ciphertext, aad):
    aesgcm = AESGCM(key) # Initialize AES-GCM under our given key.
    text = aesgcm.decrypt(nonce, ciphertext, aad) # Decrypt the data using the given nonce and additional data.
    return text # Return the ascii string plaintext.

  """

  """
  def pad (self, unpaddedData):
    byteData = bytes(unpaddedData, 'ascii') # Convert the string data to a byte array.
    length = len(byteData) # Get the length of the byte array before padding.
    length_bytes = length.to_bytes(11,"little") # Convert the length of the string data to a byte array
    modValue = length % 2048 # Calculate the mod of our length and the desired size (2048)
    byteData += bytes(2048 - modValue) # Add enough zero bytes at the end to reach our desired size.
    byteDate += length_bytes # Add the bytes holding the length to the end
    return byteData # Return the padded byte data.

  """

  """
  def unpad (self, paddedData):
    length_bytes = paddedData[2048:2058] # Carve out the length part of byte string
    length = int.from_bytes(length_bytes, "little") # Convert bytes to an integer length
    return unpad_helper(self,paddedData[0:2047],length) # Use this length to unpad the rest of the byte string

  def unpad_helper (self, paddedData, length):
    byteData = paddedData[0:length] # Slice the padding off the end, according to the length value provided to the function.
    return byteData # Return the sliced bytestring.

  """
  runSHA256(self, string)

  Helper method that runs SHA256 hashing for you.
  
  Args:
    byteArray : byte array value to hash.

  Returns:
    hashValue: the output after hashing,
  """
  def runSHA256(self, byteArray):
    sha256 = hashes.Hash(hashes.SHA256()) # Initialize the hash as a SHA256 hash function.
    sha256.update(byteArray) # Hash the string using the hash function.
    hashValue = sha256.finalize() # generate the hashed value.
    return hashValue # Return the hash value.

  """
  dump(self)

  Computes a serialized representation of the notes database
    together with a checksum.
    
  Returns: 
    data (str) : a hex-encoded serialized representation of the contents of the notes
      database (that can be passed to the constructor)
    checksum (str) : a hex-encoded checksum for the data used to protect
      against rollback attacks (up to 32 characters in length)
  """
  def dump(self):
    data = pickle.dumps(self.kvs).hex() # Generate a serialized version of the data using the pickle function.
    checksum = self.runSHA256(bytes(data, 'ascii')) # Hash the serialized data using SHA256, define this as our checksum.
    return data, checksum # Use the pickle function to serialize our data and return it. Also return the checksum.

  """
  get(self, title)

  Fetches the note associated with a title.
    
  Args:
    title (str) : the title to fetch
    
  Returns: 
    note (str) : the note associated with the requested title if
      it exists and otherwise None
  """
  def get(self, title):
    hmacTitle = self.runHMAC(self.HMACKey, bytes(title, 'ascii')) # Run HMAC on the title.
    if hmacTitle in self.kvs: # Check to see if the HMAC'd title exists in the kvs.
      paddedNote = self.AESGCMDecrypt(self.AESGCMKey, hmacTitle, self.kvs[hmacTitle], hmacTitle) # Decrypt the value corresponding to the HMAC of the title, returning a plaintext value.  
      
      #lengthTitle = self.runHMAC(self.AESGCMKey, self.runSHA256(bytes(title, 'ascii')))
      #byteLength = self.AESGCMDecrypt(self.AESGCMKey, lengthTitle, self.kvs[lengthTitle], None)
      
      #length = int.from_bytes(byteLength, 'little')
      note = self.unpad(paddedNote)
      noteString = note.decode('ascii')
      return noteString # Return the note value corresponding to the HMAC'd title.
    return None # Return nothing if the key value pair corresponding to the HMAC'd title does not exist.

  """
  set(self, title, note)

  Associates a note with a title and adds it to the database
    (or updates the associated note if the title is already
    present in the database).
       
  Args:
    title (str) : the title to set
    note (str) : the note associated with the title

  Returns:
    None

  Raises:
    ValueError : if note length exceeds the maximum
  """
  def set(self, title, note):
    if len(note) > self.MAX_NOTE_LEN: # Check the length of the note to make sure that it does not exceed the note length bounds.
      raise ValueError('Maximum note length exceeded') # Raise an value error, telling the user that their message is too long.
    hmacTitle = self.runHMAC(self.HMACKey, bytes(title, 'ascii')) # Run HMAC on the title.

    #lengthTitle = self.runHMAC(self.AESGCMKey, self.runSHA256(bytes(title, 'ascii')))

    byteData = bytes(note, 'ascii')
    #byteLength = (len(byteData)).to_bytes(2048, 'little')

    #GCMlength = self.AESGCMEncrypt(self.AESGCMKey, lengthTitle, byteLength, None)
    #self.kvs[lengthTitle] = GCMlength

    paddedNote = self.pad(note)

    GCMnote = self.AESGCMEncrypt(self.AESGCMKey, hmacTitle, paddedNote, hmacTitle) # Encrypt the note under AES-GCM. Use the HMAC'd title as the nonce (since it is non-repeating) and the additional data (to protect against swap attacks)
    # print("AES-GCM Length: {} \n".format(len(GCMnote))) * D E B U G * Used to check the length of the ciphertexts, to ensure that the padding works.
    self.kvs[hmacTitle] = GCMnote # Add a new key value pair to the kvs, where the hmac of the supplied title corresponds to the supplied note.

  """
  remove(self, title)

  Removes the note for the requested title from the database.
       
    Args:
      title (str) : the title to remove

    Returns:
      success (bool) : True if the title was removed and False if the title was
        not found
  """
  def remove(self, title):
    hmacTitle = self.runHMAC(self.HMACKey, bytes(title, 'ascii')) # Run HMAC on the title.
    #lengthTitle = self.runHMAC(self.AESGCMKey, self.runSHA256(bytes(title, 'ascii')))
    if hmacTitle in self.kvs: # Check to see if the HMAC'd title exists in the kvs.
      del self.kvs[hmacTitle] # Delete the key value pair corresponding to the HMAC'd title.
      #del self.kvs[lengthTitle] # Delete the key value pair corresponding to the HMAC'd title.
      return True # Return true, denoting that the title was successfully removed.

    return False # Otherwise return false, denoting that the title was not found in the kvs.