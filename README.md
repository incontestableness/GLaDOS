# GLaDOS

![Who are you?](https://i.imgur.com/0gbb1AH.png)


## What is GLaDOS?

GLaDOS is an application for:
* automatic, continuous scanning of Valve TF2 servers to detect malicious bots
* providing an API for aggregated player/bot statistics and automatic [TF2BD](https://github.com/PazerOP/tf2_bot_detector) player/rules list generation
* directing hathook anti-bot map queueing to more efficiently target malicious bots
* receiving [hathook](https://github.com/incontestableness/hathook-public) bot events via [portalgun](https://github.com/incontestableness/portalgun)

GLaDOS also enables users running [hathook](https://github.com/incontestableness/hathook-public) to automatically abandon matches with malicious bots in them without having to join the server first. Similarly, hathook bots also take advantage of this functionality to avoid joining matches that don't have malicious bots to kick.

It is intended to be run on a centralized server as a WSGI application for optimal performance. GLaDOS is experimental software still in alpha.


## How do I use this?

**You don't need to run your own instance of GLaDOS.** A server is already hosted and configured as the default in [portalgun](https://github.com/incontestableness/portalgun).

Simply run a local instance of [portalgun](https://github.com/incontestableness/portalgun) and your [hathook](https://github.com/incontestableness/hathook-public) installation should work as intended.

**It is strongly recommended that you use the default central server as GLaDOS takes up considerable resources when scanning TF2 servers.**


## Is the GLaDOS API publicly available?

Yes! You can access the API at https://milenko.ml/api/something where "/something" is the relevant API call.

All responses are returned in JSON format, unless an error is encountered. Most calls are cached for about 5 seconds.

Here are the publicly available API calls:
* [/popmaps/\<region_id>](https://milenko.ml/api/popmaps/0) - A list of the most popular maps for malicious bots. See [regions.json](https://github.com/incontestableness/GLaDOS/blob/master/regions.json) for available region IDs.
* [/botnames](https://milenko.ml/api/botnames) - A list of **potential** bot names, based on multiple players using the same name. This endpoint provides every name that has been seen with an (N) prefix in the past 24 hours. Use the namerules endpoint if you want times_seen limits applied and dynamically created rules that cover variants of names.
* [/namerules](https://milenko.ml/api/namerules) - An automatically generated [TF2BD](https://github.com/PazerOP/tf2_bot_detector)-compatible rules list for current bot names based on scanning Valve's TF2 servers for patterns in names.
* [/check/\<server_address>](https://milenko.ml/api/check/208.78.165.231:27015) - The number of bots on the server and a list of bot names that might not have been otherwise detected (namestealers and char-injected names).
* [/stats](https://milenko.ml/api/stats) - Cumulative statistics.


## Why did you do this?

1. In order to enable hosting anti-bots in multiple regions while still gathering aggregated statistics easily
2. Much more efficient targeting of matches with malicious bots
3. Provide for a better [hathook](https://github.com/incontestableness/hathook-public) user experience
4. Create an API that enables displaying statistics on [the website](https://milenko.ml/)
5. Science is fun


## Why the name?

["It's funny, actually, when you think about it."](https://i1.theportalwiki.net/img/3/3b/GLaDOS_escape_01_part1_nag09-1.wav) - Potato GLaDOS
