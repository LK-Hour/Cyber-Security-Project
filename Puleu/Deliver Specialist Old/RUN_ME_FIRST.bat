@echo off
echo =================================================
echo   LORN THORNPUNLEU - DELIVERY SPECIALIST
echo   Generating all HTML Smuggling + LNK Payloads
echo =================================================
echo.
python delivery_html_smuggling.py
python delivery_lnk_variants.py
echo.
echo [SUCCESS] All payloads generated in: example_payloads\
echo.
echo Next: On Kali → python3 -m http.server 80
echo Then double-click any file in example_payloads\
pause