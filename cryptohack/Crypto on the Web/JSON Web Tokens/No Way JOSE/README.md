# No Way JOSE (20pts)
## JSON Web Tokens

Let's look at JWT algorithms. The first part of a JWT is the JOSE header, and when you decode it, looks like this: {"typ":"JWT","alg":"HS256"} This tells the server it's a JWT and which algorithm to use to verify it. Can you see the issue here? The server has to process this untrusted input before i
