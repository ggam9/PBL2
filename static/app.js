
import { io } from 'https://cdn.socket.io/4.7.2/socket.io.esm.min.js';

const socket = io('http://localhost:5000/videochat', {
  reconnection: false  // 자동 재연결 방지
});
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

  // 스트림을 얻은 후 버튼 텍스트 초기화
  btnMute.textContent = localStream.getAudioTracks()[0].enabled ? '음소거' : '음소거 해제';

  //const userId = Math.random().toString(36).substr(2, 9); username을 user_id로 사용
  socket.emit('join', { user_id: username  });
  socket.emit('join_room', { room: `room-${postid}`, user_id: username });
  socket.on('reload_others', ({ user_id }) => {
    console.log(`User ${user_id} has ended the call. Reloading...`);
    // 연결 해제 후 리로드
    socket.disconnect();
    window.location.reload();
  });

  // 기존 참가자
  socket.on('all-users', ({ peers: list }) => {
    list.forEach(p => createPeer(p.sid, p.user_id, true));
  });

  // 신규 참가자 + user_id
  socket.on('new-user', ({ sid, user_id  }) => createPeer(sid, user_id, false));

  // offer
  socket.on('offer', async ({ sdp, sender }) => {
    //const pc = createPeer(sender, null, false);
    const pc = peers[sender] || createPeer(sender, null, false);
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

  socket.on('user-disconnected', ({ sid }) => {
   peers[sid]?.close();
   delete peers[sid];
   document.getElementById('video-container-' + sid)?.remove();
  });

  // 버튼 음소거 이벤트 핸들러 구현
  btnMute.addEventListener('click', () => {
   const audioTracks = localStream.getAudioTracks();
   if (audioTracks.length === 0) return;

   // 현재 상태 반전
   audioTracks.forEach(track => track.enabled = !track.enabled);

   // UI 텍스트 갱신
   const isMutedNow = !audioTracks[0].enabled;
   btnMute.textContent = isMutedNow ? '음소거 해제' : '음소거';
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
    Object.values(peers).forEach(pc => pc.close());
    Object.keys(peers).forEach(key => delete peers[key]);

   if (localStream) {
    localStream.getTracks().forEach(track => track.stop());
   }

   socket.emit('force_reload', { room: `room-${postId}`, user_id: username });

   // socket 연결 해제
   socket.disconnect();

   // 페이지 이동
   window.location.href = `/group/${postId}/studymode`;
    
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
  if (peers[sid]) return peers[sid];
  const pc = new RTCPeerConnection(config);
  peers[sid] = pc;
  
  pc.onconnectionstatechange = () => {
  if (pc.connectionState === 'disconnected' || pc.connectionState === 'failed' || pc.connectionState === 'closed') {
    console.log(`Peer ${sid} disconnected`);
    peers[sid]?.close();
    delete peers[sid];
    document.getElementById('video-container-' + sid)?.remove();
   }
  };

  localStream.getTracks().forEach(track => pc.addTrack(track, localStream));

  pc.onicecandidate = e => {
    if (e.candidate) socket.emit('ice-candidate', { candidate: e.candidate, target_sid: sid });
  };

  pc.ontrack = e => {
    let container = document.getElementById('video-container-' + sid);
    if (!container) {
      container = document.createElement('div');
      container.id = 'video-container-' + sid;
      container.style.textAlign = 'center';
      container.style.margin = '5px';
      
      const video = document.createElement('video');
      video.id = 'video-' + sid;
      video.autoplay = true;
      video.style.width = '200px';  // 크기 조정은 필요에 따라
      container.appendChild(video);

      const label = document.createElement('div');
      label.textContent = user_id || '이름 없음';
      label.style.fontSize = '14px';
      label.style.marginTop = '4px';
      container.appendChild(label);

      remoteContainer.appendChild(container);
    }
    const video = document.getElementById('video-' + sid);
    video.srcObject = e.streams[0];
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
