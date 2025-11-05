const PROXY_HOST = "127.0.0.1";
const PROXY_PORT = 7777;
const STORAGE_KEY = "proxyEnabled";//확장프로그램 로컬 저장소 상태 변수

async function applyProxySetting(enabled) {//enabled 설정되어있으면
    if (enabled) {
        const config = {
        mode: "fixed_servers", //서버모드
        rules: { singleProxy: { scheme: "http", host: PROXY_HOST, port: PROXY_PORT } }//서버 상세 규칙
        //모든 인터넷 요청을 프록시로 보냄, 스킴은 프록시로 보내는 프로토콜, 나머지는 주소
        };
        await chrome.proxy.settings.set({ value: config, scope: "regular" });//스코프 레귤러는 일반 브라우저에만 적용.
    } else {
        await chrome.proxy.settings.set({ value: { mode: "direct" }, scope: "regular" });//enabled가 아니면 다이렉트, 즉 프록시 사용말고 인터넷 연결(원래대로)
    }
    await chrome.storage.local.set({ [STORAGE_KEY]: enabled });//스토리지에 enabled 상태를 저장
}




chrome.runtime.onInstalled.addListener(async () => {//확장프로그램이 처음 설치되거나 업데이트 될때
    const { [STORAGE_KEY]: enabled } = await chrome.storage.local.get(STORAGE_KEY);//디스트럭쳐링. enabled 값을 꺼내서 읽음
    //STORAGE_KEY 변수에 따른 문자열 값을 키로써 갖는 값을 반환하는게 아니라 그냥 키값쌍을 반환함
    await applyProxySetting(Boolean(enabled));//함수 호출. enabled 가 참이면 프록시 켜고, 거짓이거나 값이 없으면 프록시 끔
});

chrome.runtime.onStartup.addListener(async () => {//브라우저 시작할때마다
    const { [STORAGE_KEY]: enabled } = await chrome.storage.local.get(STORAGE_KEY);//디스트럭쳐링
    await applyProxySetting(Boolean(enabled));//함수 호출해서 enabled가 참이면 ....
});

// popup.js에서 보내는 메시지 핸들링
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {//센더는 메시지 보낸곳, sendresponse는 메시지 보낼때
    (async () => {
        if (msg?.type === "GET_STATE") {//메시지가 존재하고 겟 스테이먼트라면
        const { [STORAGE_KEY]: enabled } = await chrome.storage.local.get(STORAGE_KEY);//enabled 값을 받아서
        sendResponse({ enabled: Boolean(enabled) });//enabled 의 불리언값을 전달
        } else if (msg?.type === "SET_STATE") { //셋 스테이먼트면
        await applyProxySetting(Boolean(msg.enabled));//프록시를 켜는 함수를 호출. enabled 값에 따라서 동작 바뀜
        sendResponse({ ok: true });//응답을 보냄
        }
    })();
    return true; //통신채널 유지를 위한 리턴값
});