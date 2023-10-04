import pickle
import os # Example on crypto documentation imports this, so I do too. 
from cryptography.hazmat.primitives import hashes, hmac # Import the SHA256 hash, and the HMAC derived from it.
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # Import the ciphers, algorithms and modes needed to perform AES.
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # Import AES-GCM.
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # Import the password generation function from the cryptography library.

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
    #print("init value: {}".format(value)) # ** D E B U G ** Print the title to compare to the HMAC one. ** D E B U G **
    hmacFunc = hmac.HMAC(key, hashes.SHA256()) # Instantiate the HMAC function.
    hmacFunc.update(value) # Use the HMAC function on the title value.
    hmacValue = hmacFunc.finalize() # Output the HMAC title.
    #print("HMAC value: {}\n".format(hmacValue)) # ** D E B U G ** Print the HMAC title. ** D E B U G **
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
    #print("new key: {}".format(newKey))
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
  def AESGCMEncrypt(self, key, nonce, text, aad):
    aesgcm = AESGCM(key) # Initialize AES-GCM under our given key.
    ciphertext = aesgcm.encrypt(nonce, bytes(text, 'ascii'), aad) # Encrypt the data using the given nonce and additional data.
    return ciphertext # Return the resulting ciphertext from encrypting under AES-GCM.

  """
  AESGCMDecrypt(self, key, nonce, ciphertext, aad)

  Decrypt a ciphertext under AES-GCM paradigm, returning a ciphertext.
  
  Args:
    key : key value that we are running AES-GCM under.
    nonce : Arbitrary but non-repeated value for the algorithm to use.
    ciphertext : The data that we are encrypting.
    aad : Additional data that should be checked for correctness upon decryption. Should help prevent tampering/swap attacks.

  returns:
    decodedText: the output after running AES-GCM, converted to an ascii string.
  """
  def AESGCMDecrypt(self, key, nonce, ciphertext, aad):
    aesgcm = AESGCM(key) # Initialize AES-GCM under our given key.
    text = aesgcm.decrypt(nonce, ciphertext, aad) # Decrypt the data using the given nonce and additional data.
    decodedText = text.decode('ascii') # Decode the text, converting to an ascii string.
    return decodedText # Return the ascii string plaintext.

  """
  runSHA256(self, string)

  Helper method that runs SHA256 hashing for you.
  
  Args:
    string : string value to hash.
  returns:
    hashValue: the output after hashing,
  """
  def runSHA256(self, string):
    sha256 = hashes.Hash(hashes.SHA256()) # Initialize the hash as a SHA256 hash function.
    sha256.update(bytes(string, 'ascii')) # Hash the string using the hash function.
    hashValue = sha256.finalize() # generate the hashed value.
    #print("hash value: {}".format(hashValue)) 
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
    return pickle.dumps(self.kvs).hex(), '' # Use the pickle function to serialize our data and return it. Should also return the checksum but not yet.

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
      # print("Note before AES-GCM decrypt: {}".format(self.kvs[hmacTitle]))
      note = self.AESGCMDecrypt(self.AESGCMKey, hmacTitle, self.kvs[hmacTitle], hmacTitle) # Decrypt the value corresponding to the HMAC of the title, returning a plaintext value.
      # print("Note after AES-GCM: {} \n".format(note))
      return note # Return the note value corresponding to the HMAC'd title.
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
    # print("Note before AES-GCM: {}".format(note))
    GCMnote = self.AESGCMEncrypt(self.AESGCMKey, hmacTitle, note, hmacTitle) # Encrypt the note under AES-GCM. Use the HMAC'd title as the nonce (since it is non-repeating) and the additional data (to protect against swap attacks)
    # print("Note after AES-GCM: {} \n".format(GCMnote))
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
    if hmacTitle in self.kvs: # Check to see if the HMAC'd title exists in the kvs.
      del self.kvs[hmacTitle] # Delete the key value pair corresponding to the HMAC'd title.
      return True # Return true, denoting that the title was successfully removed.

    return False # Otherwise return false, denoting that the title was not found in the kvs.
