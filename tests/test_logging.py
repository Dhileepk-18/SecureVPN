import unittest
import os
import logging
from monitoring.logging_config import setup_logger

class TestLoggingConfig(unittest.TestCase):

    def test_logger_creation_and_custom_security_level(self):
        log_file = "test_securevpn.log"
        if os.path.exists(log_file):
            os.remove(log_file)

        logger = setup_logger("TestLogger", log_file=log_file)

        self.assertTrue(hasattr(logger, "security"))
        logger.info("Test Info Message")
        logger.security("Test Security Event")

        self.assertTrue(os.path.exists(log_file))

        with open(log_file, "r") as f:
            content = f.read()
            self.assertIn("[INFO]", content)
            self.assertIn("[SECURITY]", content)
            self.assertIn("Test Security Event", content)

        if os.path.exists(log_file):
            os.remove(log_file)

if __name__ == '__main__':
    unittest.main()
