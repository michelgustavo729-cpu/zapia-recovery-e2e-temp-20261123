const SUPABASE_URL='https://otatwuulztvyvkvdgymx.supabase.co';
const SUPABASE_PUBLISHABLE_KEY='sb_publishable_7ooeFjEH8yw9W8tnjajGzg_i3_Z81x7';
const {createClient}=supabase;
const client=createClient(SUPABASE_URL,SUPABASE_PUBLISHABLE_KEY,{auth:{flowType:'pkce',detectSessionInUrl:true,persistSession:true,autoRefreshToken:true}});
const form=document.querySelector('#form');
const status=document.querySelector('#status');
const toggle=document.querySelector('#toggle');
const reset=document.querySelector('#reset');
const submit=document.querySelector('#submit');
const confirmWrap=document.querySelector('#confirmWrap');
const confirm=document.querySelector('#confirm');
const pass=document.querySelector('#password');
const email=document.querySelector('#email');
let mode='signin';
let recoveryActive=false;
let recoveryComplete=false;
let callbackHandled=false;
const RECOVERY_FLAG='lsp-auth-recovery-active';
async function fingerprintEmail(value){
  const normalized=String(value||'').trim().toLowerCase();
  if(!normalized||!globalThis.crypto?.subtle||!globalThis.TextEncoder)throw new Error('FINGERPRINT_UNAVAILABLE');
  const bytes=new TextEncoder().encode(normalized);
  const digest=await crypto.subtle.digest('SHA-256',bytes);
  return Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');
}
function readRecoveryMark(){
  try{
    const marker=JSON.parse(localStorage.getItem(RECOVERY_FLAG)||'null');
    const age=Date.now()-Number(marker?.requestedAt);
    return marker&&typeof marker.emailFingerprint==='string'&&/^[a-f0-9]{64}$/.test(marker.emailFingerprint)&&age>=0&&age<60*60*1000?marker:null;
  }catch(_){return null}
}
async function markRecovery(emailValue){
  try{
    const emailFingerprint=await fingerprintEmail(emailValue);
    localStorage.setItem(RECOVERY_FLAG,JSON.stringify({requestedAt:Date.now(),emailFingerprint}));
    return Boolean(readRecoveryMark());
  }catch(_){return false}
}
function clearRecoveryMark(){try{localStorage.removeItem(RECOVERY_FLAG)}catch(_){}}
function hasRecoveryMark(){return Boolean(readRecoveryMark())}
async function recoveryMatchesSession(session){
  const marker=readRecoveryMark();
  const userEmail=session?.user?.email;
  if(!marker||!userEmail)return false;
  try{return marker.emailFingerprint===await fingerprintEmail(userEmail)}catch(_){return false}
}
function hasCallbackParam(urlPart,name){return new RegExp('(?:^|[?&#])'+name+'(?:=|&|$)').test(urlPart)}
// Keep only boolean flags; never retain auth code/token values from the callback URL.
const callbackError=hasCallbackParam(location.search,'error')||hasCallbackParam(location.search,'error_code')||hasCallbackParam(location.search,'error_description')||hasCallbackParam(location.hash,'error')||hasCallbackParam(location.hash,'error_code')||hasCallbackParam(location.hash,'error_description');
const callbackCode=hasCallbackParam(location.search,'code')||hasCallbackParam(location.hash,'code');
function say(text){status.textContent=text}
function cleanCallbackUrl(){history.replaceState(history.state,document.title,location.pathname)}
function enterRecovery(){
  callbackHandled=true;
  recoveryActive=true;mode='recovery';showMode();
  say('Link válido. Defina sua nova senha abaixo.');
}
function showMode(){
  const signup=mode==='signup';
  const recovery=mode==='recovery';
  document.querySelector('#heading').textContent=recovery?'Definir nova senha':signup?'Criar conta de teste':'Acessar protótipo';
  document.querySelector('#intro').textContent=recovery?'Escolha uma nova senha. O link só funciona no mesmo navegador e dispositivo em que a recuperação foi solicitada.':'Entre com seu e-mail e senha. Esta etapa valida somente o acesso; ainda não há dados congregacionais, sincronização nem permissões administrativas.';
  document.querySelector('#emailWrap').hidden=recovery;
  email.required=!recovery;
  document.querySelector('#passwordLabel').textContent=recovery?'Nova senha (mínimo 8 caracteres)':signup?'Senha (mínimo 8 caracteres)':'Senha';
  submit.textContent=recovery?'Salvar nova senha':signup?'Criar conta':'Entrar';
  toggle.hidden=recovery;
  reset.hidden=recovery;
  confirmWrap.hidden=!signup&&!recovery;
  confirm.required=signup||recovery;
  pass.autocomplete=signup||recovery?'new-password':'current-password';
  pass.value='';
  confirm.value='';
}
toggle.addEventListener('click',()=>{mode=mode==='signin'?'signup':'signin';say('');showMode()});
form.addEventListener('submit',async e=>{
  e.preventDefault();
  say('Processando…');
  submit.disabled=true;
  try{
    if(mode==='recovery'){
      if(!recoveryActive)throw new Error('RECOVERY_SESSION_MISSING');
      if(pass.value.length<8)throw new Error('PASSWORD_TOO_SHORT');
      if(pass.value!==confirm.value)throw new Error('PASSWORD_MISMATCH');
      const {error}=await client.auth.updateUser({password:pass.value});
      if(error)throw error;
      recoveryComplete=true;
      recoveryActive=false;
      clearRecoveryMark();
      pass.value='';confirm.value='';
      let signOutFailed=false;
      try{const {error}=await client.auth.signOut({scope:'local'});signOutFailed=Boolean(error)}catch(_){signOutFailed=true}
      mode='signin';showMode();
      say(signOutFailed?'Senha atualizada. Feche esta página e entre novamente com a nova senha.':'Senha atualizada. Entre novamente com a nova senha.');
      return;
    }
    if(mode==='signup'){
      if(pass.value!==confirm.value)throw new Error('PASSWORD_MISMATCH');
      const {error}=await client.auth.signUp({email:email.value,password:pass.value,options:{emailRedirectTo:location.origin+location.pathname}});
      if(error)throw error;
      say('Se o cadastro foi aceito, verifique sua caixa de entrada para confirmar o e-mail.');
    }else{
      const {error}=await client.auth.signInWithPassword({email:email.value,password:pass.value});
      if(error)throw error;
      say('Acesso confirmado. Esta demonstração ainda não tem dados nem funções habilitadas.');
    }
  }catch(err){
    if(err.message==='PASSWORD_MISMATCH')say('As senhas não coincidem.');
    else if(err.message==='PASSWORD_TOO_SHORT')say('Use uma senha com pelo menos 8 caracteres.');
    else if(err.message==='RECOVERY_SESSION_MISSING')say('A sessão de recuperação não está ativa. Solicite um novo link no mesmo navegador e dispositivo.');
    else if(mode==='recovery')say('Não foi possível atualizar a senha. O link pode ter expirado; solicite outro e abra-o neste mesmo navegador e dispositivo.');
    else say('Não foi possível concluir. Verifique os dados e tente novamente.');
  }finally{submit.disabled=false}
});
reset.addEventListener('click',async()=>{
  if(!email.value){say('Informe seu e-mail acima para solicitar a recuperação.');email.focus();return}
  reset.disabled=true;say('Solicitando recuperação…');
  try{
    const {error}=await client.auth.resetPasswordForEmail(email.value,{redirectTo:location.origin+location.pathname});
    if(error)throw error;
    if(!await markRecovery(email.value))throw new Error('RECOVERY_MARK_UNAVAILABLE');
    say('Se a conta existir, você receberá um link. Abra-o no mesmo navegador e dispositivo em que solicitou a recuperação; links inválidos ou expirados exigem uma nova solicitação.');
  }catch(_){clearRecoveryMark();say('Não foi possível solicitar a recuperação agora. Tente novamente mais tarde.')}
  finally{reset.disabled=false}
});
client.auth.onAuthStateChange(async(event,session)=>{
  if(event==='PASSWORD_RECOVERY'&&session){
    callbackHandled=true;
    if(!callbackError&&await recoveryMatchesSession(session))enterRecovery();
    else{clearRecoveryMark();say('Não foi possível confirmar esta recuperação. Solicite um novo link neste navegador e dispositivo.');}
  }else if(event==='SIGNED_IN'&&session&&!recoveryComplete){
    if(callbackCode&&hasRecoveryMark()){
      callbackHandled=true;
      if(await recoveryMatchesSession(session))enterRecovery();
      else{clearRecoveryMark();say('O link de recuperação não corresponde à conta solicitada. Solicite um novo link para essa conta.');}
    }else if(!recoveryActive){
      say('Acesso confirmado. Esta demonstração ainda não tem dados nem funções habilitadas.');
    }
  }
});
(async()=>{
  try{
    const {data,error}=await client.auth.getSession();
    if(callbackError){clearRecoveryMark();cleanCallbackUrl();say('O link de recuperação é inválido ou expirou. Solicite um novo link.');return}
    if(callbackCode){
      cleanCallbackUrl();
      // getSession() may resolve before onAuthStateChange delivers the successful PKCE callback.
      // Keep the form locked while waiting; neither a missing session nor an old session is proof.
      // Only callback event + same-browser marker + matching account fingerprint unlocks recovery.
      if(callbackError||error){clearRecoveryMark();say('O link de recuperação é inválido ou expirou. Solicite um novo link.');}
      else if(!callbackHandled&&!recoveryActive){say('Validando o link de recuperação…');}
    }else if(location.hash){
      // Supabase or the browser may have supplied auth data in the fragment; never keep it in the address bar.
      cleanCallbackUrl();
    }
  }catch(_){
    if(callbackError||callbackCode){clearRecoveryMark();cleanCallbackUrl();say('Não foi possível validar o link. Verifique a conexão e, se necessário, solicite outro link.')}
  }
})();
