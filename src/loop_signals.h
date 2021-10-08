
#ifdef ENABLE_SMP
extern pthread_t father_id;
#endif

#ifdef ENABLE_SMP
# define IS_FATHER() pthread_equal( params->tid, father_id)
#else
/* in non smp case we have only one thread, which is the father.
 */
# define IS_FATHER() 1
#endif

#define SET_TIMEOUT( timeout, factor, infinity) \
	if (params->request_ready) \
    	   timeout = 0; \
    	else if (params->request_block) \
          timeout = (ka_timeout ? ka_timeout * factor : REQUEST_TIMEOUT * factor); \
        else { \
	   /* The father thread, has to update the timestamp. \
	    */ \
           if (IS_FATHER()) \
              timeout = (REQUEST_TIMEOUT/2) * factor; \
           else timeout = infinity; \
        }


inline static void handle_signals( server_params* params)
{

        if (params->sigchld_flag)
            sigchld_run();

#ifdef ENABLE_SMP
        /* Only the main thread handles signals.
         */
        if (pthread_equal( params->tid, father_id)) {
#endif
           /* Calculate current time. Moved here, so only one thread
            * calls this.
            */
           time(&current_time);

           if (params->sigalrm_flag)
               sigalrm_run();
           if (params->sigusr1_flag)
               sigusr1_run();
           if (params->sigterm_flag) {
               if (params->sigterm_flag == 1) {
                   sigterm_stage1_run();
               }
               if (params->sigterm_flag == 2 && !params->request_ready && !params->request_block) {
                   sigterm_stage2_run();
               }
               params->server_s[0].pending_requests = 0;
               params->server_s[1].pending_requests = 0;
           }
#ifdef ENABLE_SMP
        }
#endif

        /* the whole family calls this
         */
        if (params->sighup_flag)
            sighup_run();

}
