<?php
// Target for tests/real_php_check.py. Answers every request the same way, so a
// probe response from a healthy server is clearly distinguishable from the
// empty body a crash leaves behind.
header('Content-Type: text/plain');
echo "php2shell-ci";
