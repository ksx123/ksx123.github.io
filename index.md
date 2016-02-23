---
layout: page
title: Posts
tagline: share my post
---
{% include JB/setup %}

<div>
{% for post in site.posts %}  
    <h3><a href="{{ post.url }}">{{ post.title }}</a></h3>
    <p><small><strong>{{ post.date | date: "%B %e, %Y" }}</strong> . {{ post.category }} . <span class="author" >@{{ post.author }}</span><a href="{{ BASE_PATH }}{{ post.url }}#disqus_thread"></a></small></p>
{% endfor %}  
</div>