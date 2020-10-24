package guru.sfg.brewery.security;

import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;

public class RestURLAuthFilter extends AbstractRestAuthFilter {
    public RestURLAuthFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
    }

    @Override
    protected String getPassword(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getParameter("apiSecret");
    }

    @Override
    protected String getUserName(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getParameter("apiKey");
    }
}
