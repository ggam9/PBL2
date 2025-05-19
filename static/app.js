
import { io } from 'https://cdn.socket.io/4.7.2/socket.io.esm.min.js';

const socket = io('http://localhost:5000/videochat');
const config = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };

let localStream;
const peers = {};
const remoteContainer = document.getElementById('remoteContainer');
const localContainer  = document.getElementById('localContainer');
const chatBox = document.getElementById('chatBox');
const chatMessages = document.getElementById('chatMessages');
const chatInput = document.getElementById('chatInput');

// 버튼 요소
const btnMute  = document.getElementById('btnMute');
const btnCam   = document.getElementById('btnCam');
const btnShare = document.getElementById('btnShare');
const btnEnd   = document.getElementById('btnEnd');
const btnChat  = document.getElementById('btnChat');


const username = document.body.dataset.username;
const postid  =  document.body.dataset.postid;
const postId  = document.body.dataset.postid;

(async () => {
  try {
    // 로컬 스트림 획득
    localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
  } catch (e) {
    alert('카메라/마이크 권한을 확인해주세요.');
    return;
  }

  // 로컬 비디오 추가
  const localVideo = document.createElement('video');
  localVideo.srcObject = localStream;
  localVideo.autoplay = true;
  localVideo.muted   = true;
  localContainer.append(localVideo);

  //const userId = Math.random().toString(36).substr(2, 9); username을 user_id로 사용
  socket.emit('join', { user_id: username  });
  socket.emit('join_room', { room: `room-${postid}`, user_id: username });

  // 기존 참가자
  socket.on('all-users', ({ peers: list }) => {
    list.forEach(p => createPeer(p.sid, p.user_id, true));
  });

  // 신규 참가자
  socket.on('new-user', ({ sid }) => createPeer(sid, null, false));

  // offer
  socket.on('offer', async ({ sdp, sender }) => {
    const pc = createPeer(sender, null, false);
    await pc.setRemoteDescription(new RTCSessionDescription(sdp));
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    socket.emit('answer', { sdp: pc.localDescription, target_sid: sender });
  });

  // answer
  socket.on('answer', async ({ sdp, sender }) => {
    await peers[sender].setRemoteDescription(new RTCSessionDescription(sdp));
  });

  // ice-candidate
  socket.on('ice-candidate', async ({ candidate, sender }) => {
    await peers[sender].addIceCandidate(new RTCIceCandidate(candidate));
  });

  // 사용자 연결 해제
  socket.on('user-disconnected', ({ sid }) => {
    peers[sid]?.close();
    delete peers[sid];
    document.getElementById('video-' + sid)?.remove();
  });

  // 버튼 이벤트 핸들러 구현
  btnMute.addEventListener('click', () => {
    localStream.getAudioTracks().forEach(track => track.enabled = !track.enabled);
  });

  btnCam.addEventListener('click', () => {
    localStream.getVideoTracks().forEach(track => track.enabled = !track.enabled);
  });

  btnShare.addEventListener('click', async () => {
    try {
      const screenStream = await navigator.mediaDevices.getDisplayMedia({ video: true });
      const screenTrack = screenStream.getVideoTracks()[0];
      // 로컬 트랙 대체
      localStream.getVideoTracks()[0].stop();
      localVideo.srcObject = screenStream;
      Object.values(peers).forEach(pc => {
        const sender = pc.getSenders().find(s => s.track.kind === 'video');
        sender.replaceTrack(screenTrack);
      });
      screenTrack.onended = () => window.location.reload();
    } catch (e) {
      console.error('화면 공유 실패:', e);
    }
  });

  btnEnd.addEventListener('click', () => {
    // 모든 피어 연결 종료
    Object.values(peers).forEach(pc => pc.close());
    window.location.href = `/group/${postId}/studymode`;
    //window.location.reload();
  });
  

  btnChat.addEventListener('click', () => {
    
    chatBox.classList.toggle('show');
  });

   chatInput.addEventListener('keydown', e => {
   if (e.key === 'Enter' && chatInput.value.trim()) {
    const msg = chatInput.value.trim();
    socket.emit('chat_message', {
      room: `room-${postid}`,  // 방 이름 동적 설정
      msg: msg,
      user_id: username,
      username: username
    });
    chatInput.value = '';
   }
  });

  socket.on('chat_message', ({ username, msg }) => {
  console.log(`[RECEIVED] ${username}: ${msg}`);  // 로그 추가
  const messageElem = document.createElement('div');
  messageElem.textContent = `${username}: ${msg}`;
  chatMessages.appendChild(messageElem);
  chatMessages.scrollTop = chatMessages.scrollHeight; // 자동 스크롤
  });
 

})();

// Peer 생성 함수
function createPeer(sid, user_id, isInitiator) {
  const pc = new RTCPeerConnection(config);
  peers[sid] = pc;

  localStream.getTracks().forEach(track => pc.addTrack(track, localStream));

  pc.onicecandidate = e => {
    if (e.candidate) socket.emit('ice-candidate', { candidate: e.candidate, target_sid: sid });
  };

  pc.ontrack = e => {
    let rv = document.getElementById('video-' + sid);
    if (!rv) {
      rv = document.createElement('video');
      rv.id = 'video-' + sid;
      rv.autoplay = true;
      remoteContainer.append(rv);
    }
    rv.srcObject = e.streams[0];
  };

  if (isInitiator) {
    pc.createOffer()
      .then(o => pc.setLocalDescription(o))
      .then(() => {
        socket.emit('offer', { sdp: pc.localDescription, target_sid: sid });
      });
  }
  return pc;
}
