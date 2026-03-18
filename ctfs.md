---
layout: default
title: CTF Challenges
---

{% for ctf in site.ctfs %}
  [{{ ctf.title }}]({{ ctf.url }})
{% endfor %}