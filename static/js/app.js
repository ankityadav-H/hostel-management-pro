(function(){
 const nav=document.querySelector('[data-nav]'), toggle=document.querySelector('[data-menu-toggle]');
 if(toggle&&nav) toggle.addEventListener('click',()=>nav.classList.toggle('open'));
 document.querySelectorAll('.flash-close').forEach(b=>b.addEventListener('click',()=>b.closest('.flash').remove()));
 document.querySelectorAll('form[data-confirm]').forEach(f=>f.addEventListener('submit',e=>{if(!confirm(f.dataset.confirm||'Are you sure?'))e.preventDefault()}));
 document.querySelectorAll('a,button').forEach(el=>el.addEventListener('pointerdown',e=>{const r=document.querySelector('[data-ripple]');if(!r)return;r.style.setProperty('--x',e.clientX+'px');r.style.setProperty('--y',e.clientY+'px');r.classList.remove('active');void r.offsetWidth;r.classList.add('active')}));
 const observer=new IntersectionObserver(entries=>entries.forEach(e=>{if(e.isIntersecting){e.target.classList.add('in-view');observer.unobserve(e.target)}}),{threshold:.08});
 document.querySelectorAll('.stat-card,.panel,.room-card,.notice-large').forEach(el=>observer.observe(el));
})();
