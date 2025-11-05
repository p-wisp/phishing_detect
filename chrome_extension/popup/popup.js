const stateEl = document.getElementById("state");
const btn = document.getElementById("toggle-button");

async function refresh() {
  const resp = await chrome.runtime.sendMessage({ type: "GET_STATE" });//백그라운드로 메시지 전송, get state 타입의 메시지를 비동기로 받아옴
  const enabled = Boolean(resp?.enabled);//받은 메시지 resp안에 enabled가 있는지
  stateEl.textContent = enabled ? "ON" : "OFF";//있으면 on, 아니면 off을 상태 표기
  btn.textContent = enabled ? "끄기" : "켜기";//버튼 표시
  btn.dataset.enabled = enabled ? "1" : "0";//버튼 어트리뷰트 추가하고, 1, 0 둘중 하나의 값을 넣음
}

btn.addEventListener("click", async () => {//이벤트리스너, 클릭할때
  const enabled = btn.dataset.enabled === "1";//버튼의 enable 값이 1이라면 true를 아니면 false를 enabled에 넣음
  await chrome.runtime.sendMessage({ type: "SET_STATE", enabled: !enabled });//클릭해서 토글했으니 enabled값을 현재와 다른 값으로 스위치
  await refresh();//refresh 함수 호출해서 값을 업데이트함
});

refresh();//아이콘 열때 딱 한번 실행되는거