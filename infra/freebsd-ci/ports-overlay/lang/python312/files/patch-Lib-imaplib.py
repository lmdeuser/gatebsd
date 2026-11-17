--- Lib/imaplib.py.orig
+++ Lib/imaplib.py
@@ -129,7 +129,7 @@
 # We compile these in _mode_xxx.
 _Literal = br'.*{(?P<size>\d+)}$'
 _Untagged_status = br'\* (?P<data>\d+) (?P<type>[A-Z-]+)( (?P<data2>.*))?'
-
+_control_chars = re.compile(b'[\x00-\x1F\x7F]')
 
 
 class IMAP4:
@@ -1105,6 +1105,8 @@
             if arg is None: continue
             if isinstance(arg, str):
                 arg = bytes(arg, self._encoding)
+            if _control_chars.search(arg):
+                raise ValueError("Control characters not allowed in commands")
             data = data + b' ' + arg
 
         literal = self.literal
