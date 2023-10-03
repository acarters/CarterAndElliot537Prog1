import pickle
import os # Example on crypto documentation imports this, so I do too. 
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # Import the password generation function from the cryptography library.

class PrivNotes:
  MAX_NOTE_LEN = 2048; 
  key = None; # Variable for storing the key. Value is generated in init.
  hmacKey = None;
  AESKey = None;
  newKey3 = None;
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

    self.hmacKey = self.runHMAC(self.key, "I love the number 37") # Attempt to generate new key using AES. 
    self.AESKey = self.runHMAC(self.key, "I HATE the number 37") # Attempt to generate new key using AES.
    self.newKey3 = self.runHMAC(self.key, "I am ambivalent towards the number 37") # Attempt to generate new key using AES.

    passwordHash = self.runSHA256(password) # run SHA256 hash on password.

    # If data is blank, password cannot be wrong. If data is not blank, the password needs to be equivalent to the one used in data.
    
    if data is not None: # Case for data having a value, meaning we are loading rather than starting a new init.
      self.kvs = pickle.loads(bytes.fromhex(data)) # Load the data. Do this so we can access the password.
      if passwordHash != self.get("passwordHash"): # Get the password from data. Check if it is equal to the supplied password.
        raise ValueError("malformed serialized format"); # Return a ValueError if the password does not match.
    else: #Case for data not having a value, meaning this is a clean init
      self.set("passwordHash", passwordHash) # Add the password to the data.
  
  """
  runHMAC(self, key, value)

  Helper method that runs HMAC for you.

  Args:
    key : key value that we are running HMAC under.
    value : string value to run HMAC on.

  returns:
    hmacValue: the output after running HMAC
  """
  def runHMAC(self, key, value):
    #print("init value: {}".format(value)) # ** D E B U G ** Print the title to compare to the HMAC one. ** D E B U G **
    hmacFunc = hmac.HMAC(key, hashes.SHA256()) # Instantiate the HMAC function.
    hmacFunc.update(bytes(value, 'ascii')) # Use the HMAC function on the title value.
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
  runSHA256(self, string)

  Helper method that runs SHA256 hashing for you.
  
  Args:
    string : string value to hash.
  returns:
    hashValue: the output after hashing,
  """
  def runSHA256(self, string):
    sha256 = hashes.Hash(hashes.SHA256())
    sha256.update(bytes(string, 'ascii'))
    hashValue = sha256.finalize()
    print("hash value: {}".format(hashValue))
    return hashValue

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
    return pickle.dumps(self.kvs).hex(), ''

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

    hmacTitle = self.runHMAC(self.hmacKey, title)
    if hmacTitle in self.kvs:
      return self.kvs[hmacTitle]
    return None

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
    if len(note) > self.MAX_NOTE_LEN:
      raise ValueError('Maximum note length exceeded')
    
    hmacTitle = self.runHMAC(self.hmacKey, title)
    self.kvs[hmacTitle] = note

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

    hmacTitle = self.runHMAC(self.hmacKey, title)
    if hmacTitle in self.kvs:
      del self.kvs[hmacTitle]
      return True

    return False
