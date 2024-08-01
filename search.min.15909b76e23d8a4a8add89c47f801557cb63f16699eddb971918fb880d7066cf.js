(()=>{(function(){const s=new URLSearchParams(window.location.search),t=s.get("search").trim(),o=document.getElementById("search-input"),e=document.getElementById("search-result"),n=document.getElementById("search-result-empty");if(t)o.value=t,a(t);else return;const i={includeScore:!0,includeMatches:!0,minMatchCharLength:searchOptions.minMatchCharLength,threshold:searchOptions.threshold,keys:[{name:"title",weight:.8},{name:"content",weight:.5},{name:"tags",weight:.2},{name:"categories",weight:.2}]};function a(t){fetch("./index.json").then(e=>e.json()).then(s=>{const a=new Fuse(s,i),o=a.search(t);o.length>0?(c(t,o),n.classList.add("hidden")):(e.innerHTML="",n.classList.remove("hidden"))})}const r=`
  <article class="flex flex-col gap-y-3 p-6 mt-6 mx-2 md:mx-0 rounded-lg shadow-md bg-white dark:bg-gray-700" id="result-{{= it.index }}">
    <h2 class="text-4xl font-semibold text-slate-800 dark:text-slate-200">
      <a href="{{= it.permalink }}">{{! it.title }}</a>
    </h2>
    <h3 class="my-4 text-large text-slate-600 dark:text-slate-300">
      {{! it.snippet }}
    </h3>
    <ul class="flex flex-row flex-wrap text-slate-500 dark:text-slate-300">
      {{~ it.categories :v }}
      <li>
        <span
          class="text-sm mr-2 px-2 py-1 rounded border border-emerald-800 bg-emerald-800 text-slate-50">
          {{!v}}
        </span>
      </li>
      {{~}}
      {{~ it.tags :v }}
      <li>
        <span
          class="flex flex-row text-sm mr-2 py-1">
          {{= it.tagIcon }}
          <span class="ml-0">{{!v}}</span>
        </span>
      </li>
      {{~}}
    </ul>
  </article>
  `;function c(t,n){const s=doT.template(r),o=document.getElementById("tag-icon").innerHTML;e.innerHTML="";for(const[a,i]of n.entries()){const t=i.item,r=i.item.content;t.snippet=r.substring(0,searchOptions.summaryInclude*2)+"&hellip;",t.tagIcon=o,t.index=a,e.innerHTML+=s(t)}const i=new Mark(e);i.mark(t)}})()})()