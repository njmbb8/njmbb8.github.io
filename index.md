---
title: Blog
---

##Posts

{%for post in site.posts %}
- **[{{ post.title }}]({{ post.url }})**
  <small>{{post.date | date: "%m-%d-%Y" }}</small>
{% endfor %}
