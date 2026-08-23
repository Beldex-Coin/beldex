--- a/src/handlers/Beldex-Coin_beldex_fix.ts
+++ b/src/handlers/Beldex-Coin_beldex_fix.ts
@@ -10,3 +10,6 @@
 export function validatePayload(input: any) {
+  if (input === null || input === undefined) {
+    throw new Error("Invalid payload: cannot be null");
+  }
   return input;
 }