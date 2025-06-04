import { io } from 'https://cdn.socket.io/4.7.2/socket.io.esm.min.js';

const socket = io('http://localhost:5000/videochat', {
  reconnection: false
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

// ✅ 사용자 정보 가져오기
const username = document.body.dataset.username;
const userId   = document.body.dataset.userid;
const postId   = document.body.dataset.postid;

(async () => {
  try {
    localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
  } catch (e) {
    alert('카메라/마이크 권한을 확인해주세요.');
    return;
  }

  // 로컬 비디오 추가
  const localVideo = document.createElement('video');
  localVideo.srcObject = localStream;
  localVideo.autoplay = true;
  localVideo.muted = true;
  localContainer.append(localVideo);
  btnMute.textContent = localStream.getAudioTracks()[0].enabled ? '음소거' : '음소거 해제';

  // ✅ 실제 유저 ID와 함께 join
  socket.emit('join', { user_id: userId,username:username });
  socket.emit('join_room', { room: `room-${postId}`, user_id: userId });

  socket.on('reload_others', ({ user_id }) => {
    console.log(`User ${user_id} has ended the call. Reloading...`);
    if (socket.connected) socket.disconnect();
    window.location.reload();
  });

  socket.on('all-users', ({ peers: list }) => {
    list.forEach(p => createPeer(p.sid, p.user_id,p.username, true));
  });

  socket.on('new-user', ({ sid, user_id, username }) => createPeer(sid, user_id, username, false));

  socket.on('offer', async ({ sdp, sender, username }) => {
   const pc = peers[sender] || createPeer(sender, null, username, false);
    await pc.setRemoteDescription(new RTCSessionDescription(sdp));
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    socket.emit('answer', { sdp: pc.localDescription, target_sid: sender });
  });

  socket.on('answer', async ({ sdp, sender }) => {
    await peers[sender].setRemoteDescription(new RTCSessionDescription(sdp));
  });

  socket.on('ice-candidate', async ({ candidate, sender }) => {
    await peers[sender].addIceCandidate(new RTCIceCandidate(candidate));
  });

  socket.on('user-disconnected', ({ sid }) => {
    peers[sid]?.close();
    delete peers[sid];
    document.getElementById('video-container-' + sid)?.remove();
  });

  btnMute.addEventListener('click', () => {
    const audioTracks = localStream.getAudioTracks();
    if (audioTracks.length === 0) return;
    audioTracks.forEach(track => track.enabled = !track.enabled);
    btnMute.textContent = audioTracks[0].enabled ? '음소거' : '음소거 해제';
  });

  btnCam.addEventListener('click', () => {
    localStream.getVideoTracks().forEach(track => track.enabled = !track.enabled);
  });

  btnShare.addEventListener('click', async () => {
    try {
      const screenStream = await navigator.mediaDevices.getDisplayMedia({ video: true });
      const screenTrack = screenStream.getVideoTracks()[0];
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
    if (localStream) localStream.getTracks().forEach(track => track.stop());
    socket.emit('force_reload', { room: `room-${postId}`, user_id: userId });
    socket.disconnect();
    window.location.href = `/group/${postId}/studymode`;
  });

  btnChat.addEventListener('click', () => {
    chatBox.classList.toggle('show');
  });

  chatInput.addEventListener('keydown', e => {
    if (e.key === 'Enter' && chatInput.value.trim()) {
      const msg = chatInput.value.trim();
      socket.emit('chat_message', {
        room: `room-${postId}`,
        msg: msg,
        user_id: userId,
        username: username
      });
      chatInput.value = '';
    }
  });

  socket.on('chat_message', ({ username, msg }) => {
    console.log(`[RECEIVED] ${username}: ${msg}`);
    const messageElem = document.createElement('div');
    messageElem.textContent = `${username}: ${msg}`;
    chatMessages.appendChild(messageElem);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  });
})();

// Peer 연결 생성
function createPeer(sid, user_id,username, isInitiator) {
  if (peers[sid]) return peers[sid];
  const pc = new RTCPeerConnection(config);
  peers[sid] = pc;

  pc.onconnectionstatechange = () => {
    if (['disconnected', 'failed', 'closed'].includes(pc.connectionState)) {
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
      video.style.width = '200px';
      container.appendChild(video);
      
      // ✅ 클릭 시 확대/축소
     video.addEventListener('click', () => {
      if (video.classList.contains('zoomed')) {
        video.classList.remove('zoomed');
        video.style.width = '200px';
        video.style.zIndex = '';
        video.style.position = '';
        video.style.top = '';
        video.style.left = '';
        video.style.transform = '';
        video.style.boxShadow = '';
       } else {
        video.classList.add('zoomed');
        video.style.width = '80vw';
        video.style.position = 'fixed';
        video.style.top = '50%';
        video.style.left = '50%';
        video.style.transform = 'translate(-50%, -50%)';
        video.style.zIndex = '1000';
        video.style.boxShadow = '0 0 20px rgba(0, 0, 0, 0.5)';
      }
     });





      const label = document.createElement('div');
      label.textContent = username ? username : '이름 없음';
      label.classList.add('peer-username-label');
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
