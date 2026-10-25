async function getJson(path, body) {
  const options = body === undefined ? {} : {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)};
  const response = await fetch(path, options);
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || `HTTP ${response.status}`);
  return value;
}
function show(id, value) { document.getElementById(id).textContent = JSON.stringify(value, null, 2); }
async function action(id, fn) {
  try { await fn(); } catch (err) { document.getElementById(id).textContent = `Lỗi: ${err.message}`; }
}
const payload = () => ({message:document.getElementById('message').value,algorithm:document.getElementById('algorithm').value});
document.getElementById('toy-dh').onclick=()=>action('toy-dh-out',async()=>show('toy-dh-out',await getJson('/api/toy-dh')));
document.getElementById('ecdh').onclick=()=>action('ecdh-out',async()=>show('ecdh-out',await getJson('/api/ecdh')));
document.getElementById('encrypt').onclick=()=>action('encrypt-out',async()=>show('encrypt-out',await getJson('/api/aead',payload())));
document.getElementById('toy-ecdsa').onclick=()=>action('toy-ecdsa-out',async()=>show('toy-ecdsa-out',await getJson('/api/toy-ecdsa')));
document.getElementById('bench').onclick=()=>action('bench-out',async()=>show('bench-out',await getJson('/api/benchmarks')));
document.getElementById('mitm').onclick=()=>action('mitm-out',async()=>{
  const result=await getJson('/api/mitm',payload());const el=document.getElementById('mitm-out');el.replaceChildren();
  for(const mode of ['without_auth','with_auth']) {
    const section=document.createElement('div');section.className='log';
    const title=document.createElement('h3');title.textContent=result[mode].mode+' — '+(result[mode].mitm_success?'MITM thành công':'MITM thất bại');
    title.className=result[mode].mitm_success?'warn':'ok';section.appendChild(title);
    const pre=document.createElement('pre');pre.textContent=result[mode].log.join('\n');section.appendChild(pre);
    const detail=document.createElement('pre');detail.textContent=JSON.stringify(Object.fromEntries(Object.entries(result[mode]).filter(([k])=>k!=='log')),null,2);section.appendChild(detail);
    el.appendChild(section);
  }
}));
