document.addEventListener('DOMContentLoaded', () => {
    let state = {
        chats: [],
        activeChatId: null,
        currentUser: null,
        isRegistering: false,
    };

    const dom = {
        authContainer: document.getElementById('auth-container'),
        chatContainer: document.getElementById('chat-container'),
        loginForm: document.getElementById('login-form'),
        registerForm: document.getElementById('register-form'),
        formTitle: document.getElementById('form-title'),
        authSwitchLink: document.getElementById('show-register-link'),
        authSwitchText: document.getElementById('auth-switch-text'),
        authError: document.getElementById('auth-error'),
        authSuccess: document.getElementById('auth-success'),
        usernameDisplay: document.getElementById('username-display'),
        logoutBtn: document.getElementById('logout-btn'),
        chatList: document.getElementById('chat-list'),
        messageList: document.getElementById('message-list'),
        messageForm: document.getElementById('message-form'),
        messageInput: document.getElementById('message-input'),
        newChatBtn: document.getElementById('new-chat-btn'),
        chatHeader: document.getElementById('chat-header'),
        chatTitle: document.getElementById('chat-title'),
        renameChatBtn: document.getElementById('rename-chat-btn'),
        deleteChatBtn: document.getElementById('delete-chat-btn'),
    };

    const api = {
        async request(endpoint, method = 'GET', body = null) {
            const options = {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: body ? JSON.stringify(body) : null,
            };
            const response = await fetch(endpoint, options);
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.message || 'An API error occurred');
            }
            return data;
        },
        checkAuth: () => api.request('/api/auth/me'),
        login: (email, password) => api.request('/api/auth/login', 'POST', { email, password }),
        register: (username, email, password) => api.request('/api/auth/register', 'POST', { username, email, password }),
        logout: () => api.request('/api/auth/logout', 'POST'),
        getChats: () => api.request('/api/chats'),
        createChat: () => api.request('/api/chats', 'POST'),
        getMessages: (chatId) => api.request(`/api/chats/${chatId}/messages`),
        deleteChat: (chatId) => api.request(`/api/chats/${chatId}`, 'DELETE'),
        renameChat: (chatId, title) => api.request(`/api/chats/${chatId}`, 'PUT', { title }),
        sendMessage: (chatId, question) => api.request('/ask', 'POST', { chatId, question }),
    };

    const render = {
        authForm() {
            dom.authError.textContent = '';
            dom.authSuccess.textContent = '';
            if (state.isRegistering) {
                dom.formTitle.textContent = 'Create your account';
                dom.loginForm.classList.add('hidden');
                dom.registerForm.classList.remove('hidden');
                dom.authSwitchText.innerHTML = `Already have an account? <a href="#" id="show-register-link" class="font-medium text-coffee-brown hover:text-coffee-brown/80">Sign in</a>`;
            } else {
                dom.formTitle.textContent = 'Sign in to your account';
                dom.loginForm.classList.remove('hidden');
                dom.registerForm.classList.add('hidden');
                dom.authSwitchText.innerHTML = `Don't have an account? <a href="#" id="show-register-link" class="font-medium text-coffee-brown hover:text-coffee-brown/80">Sign up</a>`;
            }
            // Re-add event listener to the new link
            document.getElementById('show-register-link').addEventListener('click', handle.toggleAuthMode);
        },
        view() {
            if (state.currentUser) {
                dom.authContainer.classList.add('hidden');
                dom.chatContainer.classList.remove('hidden');
                dom.usernameDisplay.textContent = state.currentUser.username;
                lucide.createIcons();
            } else {
                dom.authContainer.classList.remove('hidden');
                dom.chatContainer.classList.add('hidden');
                render.authForm();
            }
        },
        chatList() {
            dom.chatList.innerHTML = '';
            if (state.chats.length === 0) {
                dom.chatList.innerHTML = '<p class="text-parchment/80 text-sm text-center px-4">No chats yet. Start a new one!</p>';
                return;
            }
            state.chats.forEach(chat => {
                const isActive = chat.id === state.activeChatId;
                const button = document.createElement('button');
                button.className = `w-full text-left p-3 rounded-lg transition-all duration-200 group relative overflow-hidden ${
                    isActive
                        ? 'bg-coffee-brown/20 border border-coffee-brown/30 shadow-lg shadow-black/20'
                        : 'hover:bg-charcoal/50 border border-transparent'
                }`;
                button.dataset.chatId = chat.id;
                button.innerHTML = `
                    <div class="relative flex items-center gap-2">
                        <i data-lucide="message-circle" class="w-4 h-4 text-coffee-brown flex-shrink-0"></i>
                        <p class="font-medium text-cream truncate text-sm">${chat.title}</p>
                    </div>
                `;
                button.addEventListener('click', () => handle.selectChat(chat.id));
                dom.chatList.appendChild(button);
            });
            lucide.createIcons();
        },
        messages(messages) {
            dom.messageList.innerHTML = '';
            if (!messages || messages.length === 0) {
                // Show a welcome/prompt message if the chat is empty
                dom.messageList.innerHTML = `
                    <div class="flex justify-center items-center h-full">
                        <div class="text-center">
                            <div class="w-16 h-16 mx-auto rounded-lg bg-coffee-brown/80 flex items-center justify-center shadow-lg shadow-black/30 mb-4">
                                <span class="text-3xl">☕</span>
                            </div>
                            <h2 class="text-2xl font-bold text-cream">Welcome to Coffee AI</h2>
                            <p class="text-parchment mt-2">Ask me anything about coffee to get started!</p>
                        </div>
                    </div>
                `;
                return;
            }
            messages.forEach(msg => {
                const el = render.createMessageElement(msg);
                dom.messageList.appendChild(el);
            });
            dom.messageList.scrollTop = dom.messageList.scrollHeight;
        },
        createMessageElement(msg) {
            const wrapper = document.createElement('div');
            const isUser = msg.sender === 'user';
            wrapper.className = `flex ${isUser ? 'justify-end' : 'justify-start'} animate-fade-in`;
            wrapper.innerHTML = `
                <div class="max-w-xl lg:max-w-2xl px-4 py-3 rounded-2xl ${
                    isUser
                        ? 'bg-coffee-brown text-cream rounded-br-none shadow-lg shadow-black/30'
                        : 'bg-charcoal text-cream rounded-bl-none shadow-lg shadow-black/30'
                }">
                    <p class="text-sm leading-relaxed whitespace-pre-line">${msg.text.trim()}</p>
                </div>
            `;
            return wrapper;
        },
        chatHeader() {
            const activeChat = state.chats.find(c => c.id === state.activeChatId);
            if (activeChat) {
                dom.chatHeader.classList.remove('hidden');
                dom.chatTitle.textContent = activeChat.title;
            } else {
                dom.chatHeader.classList.add('hidden');
            }
        }
    };

    const handle = {
        async initializeApp() {
            try {
                state.currentUser = await api.checkAuth();
                await handle.loadChats();
            } catch (error) {
                state.currentUser = null;
            } finally {
                render.view();
            }
        },
        async loadChats() {
            state.chats = await api.getChats();
            if (state.chats.length > 0 && !state.activeChatId) {
                state.activeChatId = state.chats[0].id;
            }
            if (state.activeChatId) {
                const messages = await api.getMessages(state.activeChatId);
                render.messages(messages);
            } else {
                render.messages([]);
            }
            render.chatList();
            render.chatHeader();
        },
        async login(e) {
            e.preventDefault();
            dom.authError.textContent = '';
            const email = dom.loginForm.elements.email.value;
            const password = dom.loginForm.elements.password.value;
            try {
                const { user } = await api.login(email, password);
                state.currentUser = user;
                await handle.initializeApp();
            } catch (error) {
                dom.authError.textContent = error.message;
            }
        },
        async register(e) {
            e.preventDefault();
            dom.authError.textContent = '';
            dom.authSuccess.textContent = '';
            const username = dom.registerForm.elements.username.value;
            const email = dom.registerForm.elements.email.value;
            const password = dom.registerForm.elements.password.value;
            try {
                await api.register(username, email, password);
                dom.authSuccess.textContent = 'Registration successful! Please sign in.';
                state.isRegistering = false;
                render.authForm();
            } catch (error) {
                dom.authError.textContent = error.message;
            }
        },
        async logout() {
            await api.logout();
            state.currentUser = null;
            state.chats = [];
            state.activeChatId = null;
            render.view();
        },
        toggleAuthMode(e) {
            e.preventDefault();
            state.isRegistering = !state.isRegistering;
            render.authForm();
        },
        async newChat() {
            const newChat = await api.createChat();
            state.chats.unshift(newChat);
            state.activeChatId = newChat.id;
            render.chatList();
            render.messages([]);
            render.chatHeader();
        },
        async selectChat(chatId) {
            if (state.activeChatId === chatId) return;
            state.activeChatId = chatId;
            const messages = await api.getMessages(chatId);
            render.messages(messages);
            render.chatList();
            render.chatHeader();
        },
        async sendMessage(e) {
            e.preventDefault();
            const question = dom.messageInput.value.trim();
            if (!question) return;

            if (!state.activeChatId) {
                await handle.newChat();
            }

            const userMessage = { sender: 'user', text: question };
            dom.messageList.appendChild(render.createMessageElement(userMessage));
            dom.messageList.scrollTop = dom.messageList.scrollHeight;
            dom.messageInput.value = '';

            try {
                const { user_message, ai_message, title } = await api.sendMessage(state.activeChatId, question);

                dom.messageList.appendChild(render.createMessageElement(ai_message));
                dom.messageList.scrollTop = dom.messageList.scrollHeight;

                if (title) {
                    const chat = state.chats.find(c => c.id === state.activeChatId);
                    if (chat) {
                        chat.title = title;
                        render.chatList();
                        render.chatHeader();
                    }
                }
            } catch (error) {
                console.error('Send message error:', error);
                const errorMsg = { sender: 'assistant', text: `Sorry, I encountered an error: ${error.message}` };
                dom.messageList.appendChild(render.createMessageElement(errorMsg));
                dom.messageList.scrollTop = dom.messageList.scrollHeight;
            }
        },
        async renameChat() {
            const chat = state.chats.find(c => c.id === state.activeChatId);
            if (!chat) return;

            const newTitle = prompt('Enter new chat name:', chat.title);
            if (newTitle && newTitle.trim() !== chat.title) {
                await api.renameChat(chat.id, newTitle.trim());
                chat.title = newTitle.trim();
                render.chatList();
                render.chatHeader();
            }
        },
        async deleteChat() {
            if (!state.activeChatId) return;
            if (!confirm('Are you sure you want to delete this chat?')) return;

            const deletedChatId = state.activeChatId;
            await api.deleteChat(deletedChatId);

            state.chats = state.chats.filter(c => c.id !== deletedChatId);
            state.activeChatId = state.chats.length > 0 ? state.chats[0].id : null;

            if (state.activeChatId) {
                await handle.selectChat(state.activeChatId);
            } else {
                render.chatList();
                render.messages([]);
                render.chatHeader();
            }
        }
    };

    dom.loginForm.addEventListener('submit', handle.login);
    dom.registerForm.addEventListener('submit', handle.register);
    dom.logoutBtn.addEventListener('click', handle.logout);
    dom.newChatBtn.addEventListener('click', handle.newChat);
    dom.messageForm.addEventListener('submit', handle.sendMessage);
    dom.renameChatBtn.addEventListener('click', handle.renameChat);
    dom.deleteChatBtn.addEventListener('click', handle.deleteChat);
    dom.authSwitchLink.addEventListener('click', handle.toggleAuthMode);

    handle.initializeApp();
});
