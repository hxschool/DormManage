package org.jasig.cas.client.filter;

import java.io.IOException;
import java.sql.Connection;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.validation.Assertion;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.lero.dao.DormBuildDao;
import com.lero.dao.DormManagerDao;
import com.lero.dao.StudentDao;
import com.lero.dao.UserDao;
import com.lero.model.Admin;
import com.lero.model.DormManager;
import com.lero.model.Student;
import com.lero.util.DbUtil;
import com.lero.util.HttpClientUtil;
import com.lero.util.IdcardInfoExtractor;
import com.lero.util.PropertiesUtil;
import com.lero.util.StringUtil;

public class AutoSetUserAdapterFilter implements Filter {

	DbUtil dbUtil = new DbUtil();
	UserDao userDao = new UserDao();
	StudentDao studentDao = new StudentDao();
	DormManagerDao dormManagerDao = new DormManagerDao();
	private final String password = "******";
	public void destroy() {

	}

	public final void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse,
			final FilterChain filterChain) throws IOException, ServletException {
		final HttpServletRequest request = (HttpServletRequest) servletRequest;
		final HttpServletResponse response = (HttpServletResponse) servletResponse;
		final HttpSession session = request.getSession(false);
		final Assertion assertion = session != null
				? (Assertion) session.getAttribute(org.jasig.cas.client.util.AbstractCasFilter.CONST_CAS_ASSERTION)
				: null;
		AttributePrincipal principal = (AttributePrincipal) request.getUserPrincipal();

		java.util.Map<String, Object> attributes = principal.getAttributes();
		if (attributes != null && attributes.size() > 0) {

			String username = attributes.get("login_name").toString();
			String name = attributes.get("name").toString();
			String tel = attributes.get("mobile").toString();
			String idCard = attributes.get("idCard").toString();
			String no = attributes.get("no").toString();
			IdcardInfoExtractor idcardInfo = new IdcardInfoExtractor(idCard);
			String sex = idcardInfo.getGender();
			// 判断当前登录用户是否存在,如果不存在创建用户.如果存在继续相关业务操作
			// [{roleId=6}]
			Set<String> set = null;

			String str = (String) attributes.get("roleId");
			if (str != null && !str.equals("")) {
				if (str.length() > 2 && str.indexOf('[') == 0 && str.lastIndexOf(']') == str.length() - 1) {
					String x = str.substring(1, str.length() - 1);
					String[] array = x.split(",");
					set = new HashSet(Arrays.asList(array));
				}
			}

			String teacherRoleId = PropertiesUtil.getValue("teacherRoleId");
			try {
				Connection con = dbUtil.getCon();
				// 系统默认管理员,ID永远为1,最高级管理员
				if (set != null && set.contains("1")) {
					Admin admin = new Admin(username, "******");
					Admin currentAdmin = userDao.Login(con, admin);
					if (currentAdmin == null) {
						userDao.adminAdd(con, username, password, name, "性别", tel);
						currentAdmin = userDao.Login(con, admin);
					}
					session.setAttribute("currentUserType", "admin");
					session.setAttribute("currentUser", currentAdmin);
					request.setAttribute("mainPage", "admin/blank.jsp");
					request.getRequestDispatcher("mainAdmin.jsp").forward(request, response);

				} else {
					// 如果教师包含学生创建学生角色
					if (set != null && set.contains("6")) {
						Student student = new Student(username, password);
						Student currentStudent = userDao.Login(con, student);
						if(currentStudent==null){
							String url = PropertiesUtil.getValue("api.url");
							url = url.concat("getDorm?studentNumber=").concat(no);
							
							String retVal = HttpClientUtil.get(url);
							Map<String,String> map = new Gson().fromJson(retVal, new TypeToken<Map<String, String>>() {  }.getType());
							if (map != null && map.size() > 0) {
								String json = map.get("result");
								if(!StringUtil.isEmpty(json)){
									Map<String,String> studentMap = new Gson().fromJson(json, new TypeToken<Map<String, String>>() {  }.getType());
									
									String dormbuildName = studentMap.get("dormbuild_name");
									student.setDormBuildId(DormBuildDao.dormDormBuildId(dbUtil.getCon(),dormbuildName));
									student.setDormBuildName(dormbuildName);
									student.setDormName(studentMap.get("dorm_number"));
									
								}
							}
	
							student.setName(name);
							student.setSex(sex);
							student.setStuNumber(no);
							student.setTel(tel);
							studentDao.studentAdd(con, student);
						}
						session.setAttribute("currentUserType", "student");
						session.setAttribute("currentUser", currentStudent);
						request.setAttribute("mainPage", "student/blank.jsp");
						request.getRequestDispatcher("mainStudent.jsp").forward(request, response);
						
					} else if (set.contains(teacherRoleId)) {
						// 寝室管理员
						DormManager dormManager = new DormManager(username, password);
						DormManager	currentDormManager = userDao.Login(con, dormManager);
						if(currentDormManager == null) {
							dormManager.setDormBuildId(0);
							dormManager.setDormBuildName("");
							dormManager.setDormManagerId(0);
							dormManager.setName(name);
							dormManager.setTel(tel);
							dormManager.setSex(sex);
							dormManager.setUserName(username);
							dormManager.setPassword(password);
							dormManagerDao.dormManagerAdd(con, dormManager);
							session.setAttribute("currentUserType", "dormManager");
							session.setAttribute("currentUser", currentDormManager);
							request.setAttribute("mainPage", "dormManager/blank.jsp");
							request.getRequestDispatcher("mainManager.jsp").forward(request, response);
						}
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
			}

		}
		filterChain.doFilter(request, response);
	}

	public void init(FilterConfig arg0) throws ServletException {

	}
	
	private void rememberMe(String userName, String password, String userType, HttpServletResponse response) {
		Cookie user = new Cookie("dormuser", userName+"-"+password+"-"+userType+"-"+"yes");
		user.setMaxAge(1*60*60*24*7);
		response.addCookie(user);
	}
	
	private void deleteCookie(String userName, HttpServletRequest request, HttpServletResponse response) {
		Cookie[] cookies=request.getCookies();
		for(int i=0;cookies!=null && i<cookies.length;i++){
			if(cookies[i].getName().equals("dormuser")){
				if(userName.equals(userName=cookies[i].getValue().split("-")[0])) {
					Cookie cookie = new Cookie(cookies[i].getName(), null);
					cookie.setMaxAge(0);
					response.addCookie(cookie);
					break;
				}
			}
		}
	}

}
