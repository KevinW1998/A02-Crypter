from threading import *
import random


class Encryptor(object):
    __ascii_range_start = ord('!')
    __ascii_range_end = ord('~')
    __ascii_range = __ascii_range_end - __ascii_range_start  # (~) 126 - ('!') 33

    # The valid ascii range for the input text
    # If a character occurs which is not in this range, then it will be ignored at the encryption/decryption

    def __init__(self, key):
        """
        Creates a new shift encryptor.

        :param key: The string from which the key is calculated
        """
        raw_key_val = 0
        for next_char in key:
            raw_key_val += ord(next_char)
        self.__shift_key = raw_key_val % Encryptor.__ascii_range

    def encrypt(self, text):
        """
        Will encrypt the given text.
        It will shift each ascii value of the text and returns the result.

        :param text: The given text to encrypt
        :return: The encrypted text
        """
        out_text = ""
        for c in text:
            if self.__ascii_range_start <= ord(c) <= self.__ascii_range_end:
                result_char = ord(c) + self.__shift_key
                if result_char > self.__ascii_range_end:
                    result_char -= self.__ascii_range
                out_text += chr(result_char)
            else:
                out_text += c
        return out_text

    def decrypt(self, text):
        """
        Will decrypt the given text.
        It will shift each ascii value of the text and returns the result.

        :param text: The given text to decrypt
        :return: The decrypted text
        """
        out_text = ""
        for c in text:
            if self.__ascii_range_start <= ord(c) <= self.__ascii_range_end:
                result_char = ord(c) - self.__shift_key
                if result_char < self.__ascii_range_start:
                    result_char += self.__ascii_range
                out_text += chr(result_char)
            else:
                out_text += c
        return out_text


# Providing encryption modes:
ENCRYPT_MODE = 1
DECRYPT_MODE = 2


class EncryptorWorker(Thread):
    def __init__(self, text, key, mode):
        """
        Creates a new EncryptorWorker which is based on a thread.

        :param text: The text which should be encrypt.
        :param key: The provided encryption key
        :param mode: Whether it should encrypt or decrypt
        """
        self.__encryptor_instance = Encryptor(key)
        self.__text_to_process = text

        if mode != ENCRYPT_MODE and mode != DECRYPT_MODE:
            raise ValueError("mode must be ENCRYPT_MODE or DECRYPT_MODE")

        self.__encryption_mode = mode
        self.__is_work_done = False
        self.__crypt_result = ""
        super().__init__()

    def run(self):
        if self.__encryption_mode == ENCRYPT_MODE:
            self.__crypt_result = self.__encryptor_instance.encrypt(self.__text_to_process)
        elif self.__encryption_mode == DECRYPT_MODE:
            self.__crypt_result = self.__encryptor_instance.decrypt(self.__text_to_process)
        self.__is_work_done = True

    def get_result(self):
        """
        Get the encrypted/decrypted result

        :return: the encrypted/decrypted result
        """
        if not self.__is_work_done:
            raise RuntimeError("Work is not done yet. Did you forget to call .start()?")
        return self.__crypt_result


def chunknize(msg, num_of_parts):
    """
    Splits a string into N-Slices

    :param msg: The message which should be split
    :param num_of_parts: The number of slices
    :return: A list containing N strings
    """
    part_size = len(msg) / float(num_of_parts)
    current = 0.0
    out = []

    while current < len(msg):
        out.append(msg[int(current):int(current + part_size)])
        current += part_size

    return out


if __name__ == "__main__":
    mode = 0
    while True:
        try:
            mode = int(input("What do you want to do? 0 = Exit, 1 = Encrypt message; 2 = Decrypt message\n"))
        except ValueError:
            print("Invalid input!")
            continue
        if mode < 0 or mode > 2:
            print("Invalid input!")
            continue
        break

    if mode > 0:

        mode_str = ""
        if mode == ENCRYPT_MODE:
            mode_str = "encrypt"
        elif mode == DECRYPT_MODE:
            mode_str = "decrypt"

        msg_to_encrypt = input("Which message do you want to %s? " % mode_str)
        threads_to_use = int(input("How many threads should %s the message? " % mode_str))
        possible_key = input("Enter a key or leave blank for a random key: ")
        if possible_key == "":
            for i in range(0, 4):  # Generate a small key
                possible_key += chr(random.randint(ord('a'), ord('z')))
            print("Using generated key %s" % possible_key)

        msg_parts = chunknize(msg_to_encrypt, threads_to_use)
        workers = []
        for part in msg_parts:
            workers.append(EncryptorWorker(part, possible_key, mode))

        # Execute the worker
        for worker in workers:
            worker.start()

        # Wait for all workers to be done
        for worker in workers:
            worker.join()

        # Recreate the result
        out_result = ""
        for worker in workers:
            out_result += worker.get_result()

        print("%sed result: %s" % (mode_str, out_result))
    else:
        print("Goodbye!")

