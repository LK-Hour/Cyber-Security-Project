# 🎤 CADT Cyber Security Project - Presentation Role Assignment

## 📊 Overview
**Total Duration:** 20-25 minutes (including Q&A)  
**Total Slides:** 20 slides  
**Team Members:** 7 presenters  
**Average Time per Person:** ~3 minutes

---

## 👥 Presenter Assignments

### **1. LOEM KIMHOUR (Team Leader)** - 7 minutes
**Role:** Opening, Architecture, Integration, Closing

**Slides to Present:**
- ✅ **Title Slide** (30 seconds)
  - Introduce the project title
  - Introduce all team members
  - Welcome the audience

- ✅ **Agenda** (30 seconds)
  - Overview of presentation structure
  - Set expectations for demo

- ✅ **Project Overview** (1 minute)
  - Explain the three core components
  - Educational mission and goals

- ✅ **Why This Project Matters** (1 minute)
  - Real-world relevance
  - Statistics and learning outcomes

- ✅ **System Architecture** (1.5 minutes)
  - Explain three-tier architecture
  - Show how components interact

- ✅ **Technology Stack** (1 minute)
  - Technical tools and frameworks used

- ✅ **Thank You & Q&A** (1.5 minutes)
  - Closing remarks
  - Coordinate Q&A session
  - Thank everyone

**Key Points to Emphasize:**
- Leadership role in system architecture
- Integration of red and blue teams
- C2 server development (758 lines)

---

### **2. LORN THORNPUNLEU (Puleu)** - 4 minutes
**Role:** Delivery Specialist - Attack Techniques

**Slides to Present:**
- ✅ **Team Structure** (1 minute)
  - Explain organizational chart
  - Introduce each team member's role

- ✅ **Individual Contributions** (1 minute)
  - Show contribution statistics
  - Highlight team collaboration

- ✅ **Attack Details - Delivery Specialist** (2 minutes)
  - **Deep dive into HTML Smuggling**
  - **Explain LNK masquerading technique**
  - Show technical implementation
  - Demonstrate evasion techniques

**Key Points to Emphasize:**
- HTML Smuggling: Base64 encoding, Blob API
- LNK Files: RTLO trick, icon spoofing
- Social engineering aspects
- 498 lines of delivery code

**Transition:** "Now that you've seen how we deliver the malware, let me hand it over to Homey to explain how we make it persist..."

---

### **3. CHUT HOMEY** - 3 minutes
**Role:** Persistence Specialist - Attack Techniques

**Slides to Present:**
- ✅ **Attack Details - Persistence Specialist** (3 minutes)
  - **Registry Run Keys technique**
  - **Scheduled Tasks persistence**
  - Explain multiple fallback methods
  - Show code implementation
  - Demonstrate stealth techniques

**Key Points to Emphasize:**
- Registry persistence in 3 locations
- Hidden scheduled tasks
- Multiple triggers for reliability
- 549 lines of persistence code

**Transition:** "Once we've established persistence, we need to spread. Kimkheng will show you how..."

---

### **4. LY KIMKHENG** - 3.5 minutes
**Role:** Lateral Movement Specialist - Attack Techniques

**Slides to Present:**
- ✅ **Red Team - Chimera Malware** (30 seconds)
  - Quick overview of all attack modules
  - Introduce the complete attack suite

- ✅ **Attack Kill Chain** (1 minute)
  - Explain the 9-phase attack sequence
  - Show attack timeline (~45 seconds)

- ✅ **Attack Details - Lateral Movement Specialist** (2 minutes)
  - **USB Worm propagation**
  - **SMB Network worm**
  - Explain rapid spreading mechanisms
  - Show exponential growth

**Key Points to Emphasize:**
- USB autorun.inf technique
- SMB Port 445 scanning
- Exponential network spread
- 786 lines of spreading code

**Transition:** "These are powerful attack techniques, but our blue team has strong defenses. Sakura will explain..."

---

### **5. TE SAKURA** - 3.5 minutes
**Role:** Anti-Delivery Specialist - Defense System

**Slides to Present:**
- ✅ **Blue Team - Aegis Defense** (30 seconds)
  - Quick overview of all defense modules
  - Introduce defense architecture

- ✅ **Defense Architecture** (1 minute)
  - Explain multi-layered protection
  - Defense-in-depth strategy

- ✅ **Defense Deep Dive - Anti-Delivery System** (2 minutes)
  - **File Signature Analysis** (magic numbers)
  - **Script Content Analysis** (HTML smuggling detection)
  - **Real-time Download Monitoring**
  - Show detection examples

**Key Points to Emphasize:**
- 100% detection rate for type masquerading
- Counters Puleu's HTML smuggling
- Base64 decoding and analysis
- 350 lines of anti-delivery code

**Transition:** "We detect delivery attempts, and Titya ensures malware can't persist..."

---

### **6. PANHA VIRAKTITYA (Titya)** - 3 minutes
**Role:** Anti-Persistence Specialist - Defense System

**Slides to Present:**
- ✅ **Defense Deep Dive - Core Protection Methods** (1 minute)
  - Quick overview of **Heuristic Detection**
  - Quick overview of **File Integrity Monitor**
  - Quick overview of **Network Egress Filtering**

- ✅ **Defense Deep Dive - Anti-Persistence System** (2 minutes)
  - **Registry Watchdog** (baseline monitoring)
  - **Task Scheduler Auditor** (risk scoring)
  - Show detection and removal process

**Key Points to Emphasize:**
- 100% detection rate for malicious Run keys
- Risk scoring system (≥60 = DELETE)
- Counters Homey's persistence methods
- 400 lines of anti-persistence code

**Transition:** "We prevent persistence, and now Vicheakta will show how we stop spreading..."

---

### **7. PENH SOVICHEAKTA (Vicheakta)** - 4.5 minutes
**Role:** Anti-Spreading Specialist + Results

**Slides to Present:**
- ✅ **Defense Deep Dive - Anti-Spreading System** (2 minutes)
  - **SMB Network Monitor** (Port 445 blocking)
  - **USB Sentinel** (automatic scanning)
  - Show blocking mechanisms

- ✅ **MITRE Framework Mapping** (1 minute)
  - Explain ATT&CK vs D3FEND
  - Show 1:1 mapping perfection

- ✅ **Results & Metrics** (1.5 minutes)
  - Performance dashboard
  - Detection rate, response time
  - Protection statistics

**Key Points to Emphasize:**
- 98% SMB worm blocking success
- 99% USB threat detection
- Counters Kimkheng's spreading methods
- Overall system performance metrics
- 492 lines of anti-spreading code

**Transition:** "Let's see these systems in action with our live demonstrations..."

---

## 🎬 LIVE DEMONSTRATION (Shared Responsibility)

### **Demo Coordinator: KIMHOUR + PULEU**

**Slides to Present:**
- ✅ **Demo 1 - Attack Without Defense** (2 minutes)
  - **KIMHOUR:** Narrate the attack sequence
  - **PULEU:** Run the demo (or show video)
  - Show complete system compromise

- ✅ **Demo 2 - Attack WITH Defense** (2 minutes)
  - **KIMHOUR:** Narrate defense responses
  - **SAKURA:** Point out defense actions
  - Show real-time protection

**Backup Plan:**
- Have pre-recorded video ready
- Screenshots as fallback
- One person controls, other narrates

---

## 📈 WRAP-UP SECTION (Shared)

### **Presenters: KIMHOUR + ALL TEAM**

- ✅ **Code Quality & Statistics** (1 minute)
  - **KIMHOUR:** Present statistics
  - Show 5,542 lines of code breakdown

- ✅ **Key Learnings** (1 minute)
  - **Everyone contributes ONE learning each:**
    - **Kimhour:** System architecture & integration
    - **Puleu:** Social engineering psychology
    - **Homey:** Windows persistence mechanisms
    - **Kimkheng:** Network propagation
    - **Sakura:** Detection techniques
    - **Titya:** Registry monitoring
    - **Vicheakta:** Network security

- ✅ **Future Enhancements** (1 minute)
  - **KIMHOUR:** Present future roadmap
  - Show ambition and vision

---

## 📋 Presentation Flow Summary

| # | Presenter | Slides | Time | Section |
|---|-----------|--------|------|---------|
| 1 | **Kimhour** | Title, Agenda, Overview, Why It Matters, Architecture, Tech Stack | 5 min | Introduction & Architecture |
| 2 | **Puleu** | Team Structure, Contributions, Delivery Details | 4 min | Team & Delivery Attack |
| 3 | **Homey** | Persistence Details | 3 min | Persistence Attack |
| 4 | **Kimkheng** | Red Team Overview, Kill Chain, Lateral Movement Details | 3.5 min | Overview & Lateral Movement |
| 5 | **Sakura** | Blue Team, Defense Architecture, Anti-Delivery | 3.5 min | Defense Overview & Anti-Delivery |
| 6 | **Titya** | Core Protection, Anti-Persistence | 3 min | Core Defense & Anti-Persistence |
| 7 | **Vicheakta** | Anti-Spreading, MITRE Mapping, Results | 4.5 min | Anti-Spreading & Results |
| **ALL** | Demo Scenarios | 4 min | **LIVE DEMONSTRATIONS** |
| **ALL** | Code Stats, Learnings, Future | 3 min | Learnings & Future |
| **Kimhour** | Thank You & Q&A | 1.5 min | Closing & Q&A |
| | | **TOTAL:** | **~35 min** | **(including buffer)** |

---

## 🎯 Coordination Guidelines

### Before Presentation:

**Team Rehearsal (MANDATORY):**
- ✅ Practice together at least 2 times
- ✅ Time each person's section
- ✅ Practice smooth transitions between speakers
- ✅ Test demo equipment

**Individual Preparation:**
- ✅ Memorize YOUR slides (don't read from screen)
- ✅ Prepare 2-3 talking points per slide
- ✅ Know your transition line to next speaker
- ✅ Have backup notes (but don't rely on them)

**Technical Setup:**
- ✅ **Kimhour:** Control laptop, advance slides
- ✅ **Puleu:** Backup laptop ready for demo
- ✅ Have demo video ready (if live demo fails)
- ✅ Test projector/screen compatibility

### During Presentation:

**Speaking Order (Standing Positions):**
```
[Projector Screen]
─────────────────────────────────────
  Homey  Puleu  KIMHOUR  Sakura  Titya
            ↓
      (Center, controls slides)
            
  Kimkheng                    Vicheakta
  (Left side)                 (Right side)
```

**Transition Protocol:**
1. Finish your last point
2. Use transition sentence (prepared)
3. Say next presenter's name clearly
4. Make eye contact and gesture to them
5. Move aside (don't walk in front of screen)

**Example Transitions:**
- Puleu → Homey: *"Now that you've seen how we deliver the malware, let me hand it over to **Homey** to explain how we make it persist on the system."*
- Homey → Kimkheng: *"Once we've established persistence, we need to spread to other systems. **Kimkheng** will demonstrate our lateral movement techniques."*
- Kimkheng → Sakura: *"These are powerful attack techniques, but our blue team has developed equally sophisticated defenses. **Sakura** will explain our anti-delivery system."*

### Q&A Session Management:

**Question Distribution:**
- **Kimhour (Coordinator):** Assign questions to appropriate team member
- **Technical questions:** Direct to person who implemented it
- **General questions:** Anyone can answer
- **Difficult questions:** Team can confer briefly

**Example Q&A Handling:**
```
Professor: "How does your heuristic detection avoid false positives?"

Kimhour: "Great question! Titya implemented our core detection system, 
         so I'll let him explain the specific mechanisms we use."

Titya: [Answers question about threshold tuning and testing]
```

---

## 💡 Individual Speaking Tips

### **KIMHOUR (Leader):**
- ✅ Set confident, professional tone
- ✅ Make eye contact with professor
- ✅ Coordinate transitions smoothly
- ✅ Be ready to help if anyone gets stuck

### **PULEU (Delivery):**
- ✅ Explain social engineering clearly
- ✅ Show enthusiasm for evasion techniques
- ✅ Use real-world phishing examples

### **HOMEY (Persistence):**
- ✅ Emphasize stealth and reliability
- ✅ Explain why multiple methods needed
- ✅ Connect to real malware tactics

### **KIMKHENG (Lateral Movement):**
- ✅ Show excitement about exponential spread
- ✅ Use network diagrams effectively
- ✅ Explain real-world worm scenarios

### **SAKURA (Anti-Delivery):**
- ✅ Contrast detection vs evasion
- ✅ Show pride in 100% detection rate
- ✅ Explain technical details clearly

### **TITYA (Anti-Persistence):**
- ✅ Emphasize proactive monitoring
- ✅ Explain risk scoring logic
- ✅ Show how defense counters attack

### **VICHEAKTA (Anti-Spreading):**
- ✅ Demonstrate network security knowledge
- ✅ Present metrics confidently
- ✅ Summarize overall system success

---

## 🚨 Contingency Plans

### If Someone is Absent:
**Backup Presenters:**
- Puleu's slides → **Kimhour**
- Homey's slides → **Puleu** or **Kimkheng**
- Kimkheng's slides → **Homey**
- Sakura's slides → **Titya** or **Vicheakta**
- Titya's slides → **Sakura**
- Vicheakta's slides → **Titya**

### If Demo Fails:
1. **Switch to pre-recorded video immediately**
2. Don't apologize excessively - technology happens
3. Narrate the video confidently
4. Have screenshots ready as last resort

### If Running Over Time:
**Skip these slides (if needed):**
- Team Structure - brief verbal summary
- Code Quality & Statistics - mention key numbers only
- Future Enhancements - skip entirely

### If Running Under Time:
**Expand these sections:**
- Add more technical details in demos
- Explain code snippets line-by-line
- Share more real-world scenarios
- Open Q&A earlier

---

## 📞 Contact & Coordination

**WhatsApp Group:** CADT Cyber Security Team  
**Final Rehearsal:** December [DATE] at [TIME]  
**Presentation Day:** December [DATE] at [TIME]

**Day-Before Checklist:**
- ✅ Confirm everyone can attend
- ✅ Test presentation on actual equipment
- ✅ Review this role assignment document
- ✅ Get good sleep!

**Morning-Of Checklist:**
- ✅ Arrive 15 minutes early
- ✅ Dress professionally
- ✅ Test equipment one last time
- ✅ Calm nerves, support each other
- ✅ Brief review of transitions

---

## 🏆 Success Criteria

**We've succeeded when:**
- ✅ Everyone presents their section confidently
- ✅ Transitions are smooth and professional
- ✅ Demo works (or backup executed well)
- ✅ Professor and classmates understand the project
- ✅ Q&A handled competently
- ✅ Team shows unity and collaboration
- ✅ Time management is good (not too long/short)

---

## 💪 Motivational Note

**Remember:** You've built an incredible project together. This presentation is your chance to showcase not just technical skills, but teamwork, problem-solving, and professionalism. 

**Each person's part is crucial.** Red team shows the threat, blue team shows the solution, and together we demonstrate complete understanding of cybersecurity.

**Trust your teammates.** If someone stumbles, others can help. We're a team.

**Be proud.** 5,542 lines of code, 7 specialized modules, perfect MITRE mapping - this is graduate-level work!

---

## 🎓 Final Words from Team Leader

> "We've spent 5 weeks building this system. We know it inside and out. Tomorrow, we don't just present code - we tell the story of how cybersecurity really works: attack and defense, offense and protection, red and blue. Let's show Professor Reatrey and everyone what CADT students can achieve when we work together."
> 
> **— Loem Kimhour, Team Leader**

---

**Good luck to everyone! Let's make CADT proud! 🚀🛡️**

---

**Document Version:** 1.0  
**Last Updated:** December 16, 2025  
**Approved by:** Team Leader Loem Kimhour
